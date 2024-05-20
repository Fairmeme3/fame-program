use anchor_lang::prelude::*;
use anchor_lang::solana_program::native_token::LAMPORTS_PER_SOL;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_lang::system_program::{transfer, Transfer};
use anchor_spl::associated_token::{get_associated_token_address, AssociatedToken};
use anchor_spl::metadata::mpl_token_metadata::types::DataV2;
use anchor_spl::metadata::{create_metadata_accounts_v3, CreateMetadataAccountsV3, Metadata};
use anchor_spl::token::spl_token::instruction::AuthorityType;
use anchor_spl::token::{
    burn, mint_to, set_authority, sync_native, transfer as spl_tranfer, Burn, Mint, MintTo,
    SetAuthority, SyncNative, Token, TokenAccount, Transfer as SplTransfer,
};
use raydium_contract_instructions::amm_instruction;
use solana_program::pubkey;

pub const DEFAULT_LP_OPEN_TIME_DELAY: u64 = 3600;
pub const DEFAULT_FINAL_REFUND_DELAY: i64 = 3600 * 24;
pub const DEFAULT_MIN_FUNDS_PER_USER: u64 = LAMPORTS_PER_SOL / 10;
pub const DEFAULT_MAX_FUNDS_PER_USER: u64 = LAMPORTS_PER_SOL * 10;
pub const INIT_COST: u64 = 2 * LAMPORTS_PER_SOL / 100;

pub const MIN_FUNDS_THRESHOLD: u64 = 100 * LAMPORTS_PER_SOL;
pub const MAX_FUNDS_THRESHOLD: u64 = 1000000 * LAMPORTS_PER_SOL;

pub const MIN_PROTOCOL_FEE: u64 = 33 * LAMPORTS_PER_SOL / 10;
pub const LP_FEE: u64 = 5 * LAMPORTS_PER_SOL / 10;
pub const FAME_VAULT: Pubkey = pubkey!("7apbWmrFuxQvoC2bqMCK7C2UbfohKAU8LX9JKwNm5gR");

pub const TOKEN_DECIMALS: u8 = 6;
pub const TOKEN_TOTAL_SUPPLY: u64 = 10u64.pow(9) * 10u64.pow(TOKEN_DECIMALS as u32);
declare_id!("BxydrxKLHNsBakkndFZXjrQhVBanHwvFAMsv4ov2XxCj");

fn multiply_and_divide(a: u64, b: u64, c: u64) -> u64 {
    // Try converting to u128
    if let (Ok(a_u128), Ok(b_u128), Ok(c_u128)) =
        (u128::try_from(a), u128::try_from(b), u128::try_from(c))
    {
        // Use u128 for calculation
        let result_u128: u128 = (a_u128 * b_u128) / c_u128;
        // Convert back to u64
        if let Ok(result_u64) = u64::try_from(result_u128) {
            return result_u64;
        }
    }
    // If conversion or calculation overflows, return u64's MIN value
    u64::MIN
}
#[program]
mod fame {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        token_metadata_uri: String,
        token_name: String,
        token_symbol: String,
        duration: i64,
        min_funds_threshold: u64,
        max_funds_cap: u64,
    ) -> Result<()> {
        let start_timestamp = Clock::get()?.unix_timestamp;
        let vault = &mut ctx.accounts.vault;
        let fame_status = &mut ctx.accounts.fame_status;
        let fund_raising = &mut ctx.accounts.fund_raising;
        let signer = &mut ctx.accounts.signer;
        let system_program = &ctx.accounts.system_program;

        require!(
            min_funds_threshold >= MIN_FUNDS_THRESHOLD && max_funds_cap <= MAX_FUNDS_THRESHOLD,
            FameError::FundsThresholdInvalid
        );
        require!(
            max_funds_cap >= min_funds_threshold,
            FameError::FundsCapInvalid
        );
        require!(
            token_name.len() <= 10 && token_symbol.len() <= 10,
            FameError::TokenNameInvalid
        );
        require!(
            duration >= 3600 && duration <= 3600 * 72,
            FameError::DurationInvalid
        );

        transfer(
            CpiContext::new(
                system_program.to_account_info(),
                Transfer {
                    from: signer.to_account_info(),
                    to: vault.to_account_info(),
                },
            ),
            INIT_COST,
        )?;
        fame_status.fund_raising = fund_raising.key();
        fame_status.current_funding_amount = 0;
        fame_status.max_funding_amount = 0;
        fame_status.funding_user_count = 0;
        fame_status.refunding_user_count = 0;
        fame_status.assigned_token_user_count = 0;
        fame_status.token_created = false;
        fame_status.lp_created = false;

        fund_raising.creator = signer.key();
        fund_raising.token_name = token_name;
        fund_raising.token_symbol = token_symbol;
        fund_raising.token_metadata_uri = token_metadata_uri;
        fund_raising.token_decimal = TOKEN_DECIMALS;
        fund_raising.token_total_supply = TOKEN_TOTAL_SUPPLY;
        fund_raising.start_timestamp = start_timestamp;
        fund_raising.end_timestamp = start_timestamp + duration;
        fund_raising.final_refund_timestamp =
            start_timestamp + duration + DEFAULT_FINAL_REFUND_DELAY;
        fund_raising.lp_open_time_delay = DEFAULT_LP_OPEN_TIME_DELAY;
        fund_raising.min_funds_threshold = min_funds_threshold;
        fund_raising.max_funds_cap = max_funds_cap;
        fund_raising.min_funds_per_user = DEFAULT_MIN_FUNDS_PER_USER;
        fund_raising.max_funds_per_user = DEFAULT_MAX_FUNDS_PER_USER;
        Ok(())
    }

    pub fn buy(ctx: Context<Buy>, amount: u64) -> Result<()> {
        let slot = Clock::get()?.unix_timestamp;
        let fund_raising = &mut ctx.accounts.fund_raising;
        msg!("current slot: {}", slot);
        require!(
            slot > fund_raising.start_timestamp,
            FameError::NotStartedYet
        );
        require!(slot < fund_raising.end_timestamp, FameError::HasEnded);
        require!(
            amount >= fund_raising.min_funds_per_user,
            FameError::LessThanMinFundsPerUser
        );

        let current_share = &mut ctx.accounts.share;
        require!(
            amount + current_share.funding_amount <= fund_raising.max_funds_per_user,
            FameError::MoreThanMaxFundsPerUser,
        );

        let vault = &mut ctx.accounts.vault;
        let fame_status = &mut ctx.accounts.fame_status;
        let signer = &mut ctx.accounts.signer;
        let system_program = &ctx.accounts.system_program;
        let vault_balance_before = vault.get_lamports();

        transfer(
            CpiContext::new(
                system_program.to_account_info(),
                Transfer {
                    from: signer.to_account_info(),
                    to: vault.to_account_info(),
                },
            ),
            amount,
        )?;

        let vault_balance_after = vault.get_lamports();

        require_eq!(vault_balance_after, vault_balance_before + amount);

        if current_share.funding_amount == 0 {
            fame_status.funding_user_count += 1;

            current_share.owner = signer.key();
            current_share.share_amount = 0;
            current_share.has_refunded = false;
            current_share.has_assigned_token = false;
        }
        current_share.funding_amount += amount;
        fame_status.current_funding_amount += amount;
        fame_status.max_funding_amount += amount;
        Ok(())
    }

    pub fn create_token(ctx: Context<CreateToken>) -> Result<()> {
        let slot = Clock::get()?.unix_timestamp;
        let fund_raising = &mut ctx.accounts.fund_raising;
        require!(slot > fund_raising.end_timestamp, FameError::NotEndedYet);
        let fame_status = &mut ctx.accounts.fame_status;
        require!(
            fame_status.max_funding_amount >= fund_raising.min_funds_threshold,
            FameError::NotReachedMinFundsThreshold
        );
        let fame_vault: &mut AccountInfo = &mut ctx.accounts.fame_vault;
        require!(!fame_status.token_created, FameError::AlreadyCreatedToken);
        require_eq!(fame_vault.key(), FAME_VAULT, FameError::NotFameVault);

        let vault = &mut ctx.accounts.vault;
        let system_program = &ctx.accounts.system_program;
        let fund_raising_key = fund_raising.key();

        let vault_bump = &[ctx.bumps.vault];
        let vault_seeds: &[&[u8]] = &[b"vault".as_ref(), fund_raising_key.as_ref(), vault_bump];
        let vault_signer_seeds = &[&vault_seeds[..]];

        let protocol_fee = if fame_status.max_funding_amount * 8 / 1000 > MIN_PROTOCOL_FEE {
            fame_status.max_funding_amount * 8 / 1000
        } else {
            MIN_PROTOCOL_FEE
        };

        transfer(
            CpiContext::new_with_signer(
                system_program.to_account_info(),
                Transfer {
                    from: vault.to_account_info(),
                    to: fame_vault.to_account_info(),
                },
                vault_signer_seeds,
            ),
            protocol_fee,
        )?;
        fame_status.current_funding_amount -= protocol_fee;

        msg!("Running mint_to");
        let bump = &[ctx.bumps.mint];
        let seeds: &[&[u8]] = &[b"mint".as_ref(), fund_raising_key.as_ref(), bump];
        let signer_seeds = &[&seeds[..]];

        mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    authority: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.vault_associated_token.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                },
                signer_seeds,
            ),
            fund_raising.token_total_supply,
        )?;

        msg!("Run create metadata accounts v3");
        create_metadata_accounts_v3(
            CpiContext::new_with_signer(
                ctx.accounts.metadata_program.to_account_info(),
                CreateMetadataAccountsV3 {
                    payer: ctx.accounts.signer.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    metadata: ctx.accounts.metadata.to_account_info(),
                    mint_authority: ctx.accounts.mint.to_account_info(),
                    update_authority: ctx.accounts.mint.to_account_info(),
                    system_program: ctx.accounts.system_program.to_account_info(),
                    rent: ctx.accounts.rent.to_account_info(),
                },
                signer_seeds,
            ),
            DataV2 {
                name: String::from(&fund_raising.token_name),
                symbol: String::from(&fund_raising.token_symbol),
                uri: String::from(&fund_raising.token_metadata_uri),
                seller_fee_basis_points: 0,
                creators: None,
                collection: None,
                uses: None,
            },
            true,
            true,
            None,
        )?;
        set_authority(
            CpiContext::new_with_signer(
                ctx.accounts.metadata_program.to_account_info(),
                SetAuthority {
                    account_or_mint: ctx.accounts.mint.to_account_info(),
                    current_authority: ctx.accounts.mint.to_account_info(),
                },
                signer_seeds,
            ),
            AuthorityType::MintTokens,
            None,
        )?;
        fame_status.token_created = true;
        Ok(())
    }

    pub fn assign_token(ctx: Context<AssignToken>) -> Result<()> {
        let fame_status = &mut ctx.accounts.fame_status;
        require!(fame_status.lp_created, FameError::LpNotCreatedYet);

        let share = &mut ctx.accounts.share;
        require!(!share.has_assigned_token, FameError::AlreadyAssignedToken);
        let destination = &mut ctx.accounts.destination;

        require_eq!(
            get_associated_token_address(&destination.key(), &ctx.accounts.mint.key()),
            ctx.accounts.to_associated_token.key(),
            FameError::IncorrectTokenVault
        );
        let fund_raising = &mut ctx.accounts.fund_raising;
        let (expected_share, _bump_seed) = Pubkey::find_program_address(
            &[
                b"share".as_ref(),
                fund_raising.key().as_ref(),
                destination.key().as_ref(),
            ],
            &ctx.program_id,
        );

        require_eq!(share.owner, destination.key(), FameError::NotOwner);
        require_eq!(
            expected_share.key(),
            share.key(),
            FameError::IncorrectTokenVault
        );

        let fund_raising_key = fund_raising.key();
        let bump = &[ctx.bumps.vault];
        let seeds: &[&[u8]] = &[b"vault".as_ref(), fund_raising_key.as_ref(), bump];
        let signer_seeds = &[&seeds[..]];

        share.share_amount = multiply_and_divide(
            fund_raising.token_total_supply / 2,
            share.funding_amount,
            fame_status.max_funding_amount,
        );
        let protocol_fee = if fame_status.max_funding_amount * 8 / 1000 > MIN_PROTOCOL_FEE {
            fame_status.max_funding_amount * 8 / 1000
        } else {
            MIN_PROTOCOL_FEE
        };

        let real_max_funding_amount = fame_status.max_funding_amount - protocol_fee - LP_FEE;

        if real_max_funding_amount > fund_raising.max_funds_cap {
            let refund_amount = multiply_and_divide(
                real_max_funding_amount - fund_raising.max_funds_cap,
                share.funding_amount,
                fame_status.max_funding_amount,
            );

            let yielded_funding_amount = share.funding_amount - refund_amount;

            let vault = &mut ctx.accounts.vault;
            let system_program = &ctx.accounts.system_program;

            let fund_raising = &mut ctx.accounts.fund_raising;
            let fund_raising_key = fund_raising.key();
            let bump = &[ctx.bumps.vault];
            let seeds: &[&[u8]] = &[b"vault".as_ref(), fund_raising_key.as_ref(), bump];
            let signer_seeds = &[&seeds[..]];

            let vault_balance_before = vault.get_lamports();

            transfer(
                CpiContext::new(
                    system_program.to_account_info(),
                    Transfer {
                        from: vault.to_account_info(),
                        to: destination.to_account_info(),
                    },
                )
                .with_signer(signer_seeds),
                refund_amount,
            )?;
            let vault_balance_after = vault.get_lamports();
            require_eq!(vault_balance_after, vault_balance_before - refund_amount);

            share.funding_amount = yielded_funding_amount;
            fame_status.current_funding_amount -= refund_amount;
        }

        spl_tranfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                SplTransfer {
                    from: ctx.accounts.vault_associated_token.to_account_info(),
                    to: ctx.accounts.to_associated_token.to_account_info(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
                signer_seeds,
            ),
            share.share_amount,
        )?;
        share.has_assigned_token = true;
        fame_status.assigned_token_user_count += 1;
        Ok(())
    }

    pub fn refund(ctx: Context<Refund>) -> Result<()> {
        let slot = Clock::get()?.unix_timestamp;
        let fund_raising = &mut ctx.accounts.fund_raising;
        require!(slot > fund_raising.end_timestamp, FameError::NotEndedYet);
        let current_share = &mut ctx.accounts.share;
        require!(
            !current_share.has_refunded && current_share.funding_amount > 0,
            FameError::AlreadyRefunded
        );

        let vault = &mut ctx.accounts.vault;
        let fame_status = &mut ctx.accounts.fame_status;
        require!(
            fame_status.max_funding_amount < fund_raising.min_funds_threshold
                || (slot > fund_raising.final_refund_timestamp && !fame_status.lp_created),
            FameError::ReachedMinFundsThreshold
        );
        let destination = &mut ctx.accounts.destination;
        require_eq!(current_share.owner, destination.key(), FameError::NotOwner);

        let system_program = &ctx.accounts.system_program;
        let fund_raising = &mut ctx.accounts.fund_raising;
        let fund_raising_key = fund_raising.key();
        let bump = &[ctx.bumps.vault];
        let seeds: &[&[u8]] = &[b"vault".as_ref(), fund_raising_key.as_ref(), bump];
        let signer_seeds = &[&seeds[..]];

        let vault_balance_before = vault.get_lamports();

        transfer(
            CpiContext::new_with_signer(
                system_program.to_account_info(),
                Transfer {
                    from: vault.to_account_info(),
                    to: destination.to_account_info(),
                },
                signer_seeds,
            ),
            current_share.funding_amount,
        )?;

        let vault_balance_after = vault.get_lamports();

        require_eq!(
            vault_balance_after,
            vault_balance_before - current_share.funding_amount
        );

        fame_status.refunding_user_count += 1;
        fame_status.current_funding_amount -= current_share.funding_amount;

        current_share.has_refunded = true;
        current_share.funding_amount = 0;

        Ok(())
    }

    pub fn initialize_lp(ctx: Context<InitializeLp>, nonce: u8) -> Result<()> {
        let fame_status = &mut ctx.accounts.fame_status;
        require!(fame_status.token_created, FameError::TokenNotCreatedYet);
        require!(!fame_status.lp_created, FameError::AlreadyCreatedLp);
        let fund_raising = &mut ctx.accounts.fund_raising;
        let fund_raising_key = fund_raising.key();

        let bump = &[ctx.bumps.vault];
        let seeds: &[&[u8]] = &[b"vault".as_ref(), fund_raising_key.as_ref(), bump];
        let signer_seeds = &[&seeds[..]];

        let protocol_fee = if fame_status.max_funding_amount * 8 / 1000 > MIN_PROTOCOL_FEE {
            fame_status.max_funding_amount * 8 / 1000
        } else {
            MIN_PROTOCOL_FEE
        };
        let real_max_funding_amount = fame_status.max_funding_amount - protocol_fee - LP_FEE;

        let wsol_amount = if real_max_funding_amount > fund_raising.max_funds_cap {
            fund_raising.max_funds_cap
        } else {
            real_max_funding_amount
        };

        msg!("Running wrap sol to wsol");
        transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: ctx.accounts.user_pc_token_account.to_account_info(),
                },
                signer_seeds,
            ),
            wsol_amount,
        )?;

        // Sync the native token to reflect the new SOL balance as wSOL
        sync_native(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            SyncNative {
                account: ctx.accounts.user_pc_token_account.to_account_info(),
            },
            signer_seeds,
        ))?;

        let opentime = Clock::get()?.unix_timestamp as u64 + fund_raising.lp_open_time_delay;
        let coin_amount: u64 = fund_raising.token_total_supply / 2;
        let pc_amount: u64 = wsol_amount;

        msg!("Running raydium amm initialize2");
        let initialize_ix = amm_instruction::initialize2(
            ctx.accounts.amm_program.key,
            ctx.accounts.amm.key,
            ctx.accounts.amm_authority.key,
            ctx.accounts.amm_open_orders.key,
            ctx.accounts.lp_mint.key,
            ctx.accounts.coin_mint.key,
            ctx.accounts.pc_mint.key,
            ctx.accounts.pool_coin_token_account.key,
            ctx.accounts.pool_pc_token_account.key,
            ctx.accounts.amm_target_orders.key,
            ctx.accounts.amm_config.key,
            ctx.accounts.fee_destination.key,
            ctx.accounts.serum_program.key,
            ctx.accounts.serum_market.key,
            ctx.accounts.vault.key,
            ctx.accounts.user_coin_token_account.key,
            ctx.accounts.user_pc_token_account.key,
            &ctx.accounts.user_lp_token_account.key(),
            nonce,
            opentime,
            pc_amount,
            coin_amount,
        )?;
        let account_infos = [
            ctx.accounts.amm_program.clone(),
            ctx.accounts.amm.clone(),
            ctx.accounts.amm_authority.clone(),
            ctx.accounts.amm_open_orders.clone(),
            ctx.accounts.lp_mint.clone(),
            ctx.accounts.coin_mint.clone(),
            ctx.accounts.pc_mint.clone(),
            ctx.accounts.pool_coin_token_account.clone(),
            ctx.accounts.pool_pc_token_account.clone(),
            ctx.accounts.amm_target_orders.clone(),
            ctx.accounts.amm_config.clone(),
            ctx.accounts.fee_destination.clone(),
            ctx.accounts.serum_program.clone(),
            ctx.accounts.serum_market.clone(),
            ctx.accounts.vault.to_account_info().clone(),
            ctx.accounts.user_coin_token_account.clone(),
            ctx.accounts.user_pc_token_account.clone(),
            ctx.accounts.user_lp_token_account.clone(),
            ctx.accounts.token_program.to_account_info().clone(),
            ctx.accounts.system_program.to_account_info().clone(),
            ctx.accounts
                .associated_token_program
                .to_account_info()
                .clone(),
            ctx.accounts.rent.to_account_info().clone(),
        ];
        invoke_signed(&initialize_ix, &account_infos, signer_seeds)?;

        fame_status.lp_created = true;
        fame_status.current_funding_amount -= wsol_amount;
        Ok(())
    }

    pub fn burn_lp_token(ctx: Context<BurnLpToken>) -> Result<()> {
        msg!("Burning raydium amm LP token");
        require!(
            ctx.accounts.fame_status.lp_created,
            FameError::LpNotCreatedYet
        );
        let fund_raising = &mut ctx.accounts.fund_raising;
        let fund_raising_key = fund_raising.key();

        let bump = &[ctx.bumps.vault];
        let seeds: &[&[u8]] = &[b"vault".as_ref(), fund_raising_key.as_ref(), bump];
        let signer_seeds = &[&seeds[..]];
        burn(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    from: ctx.accounts.user_lp_token_account.to_account_info(),
                    mint: ctx.accounts.lp_mint.to_account_info(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
                signer_seeds,
            ),
            ctx.accounts.user_lp_token_account.amount,
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(token_metadata_uri: String)]
pub struct Initialize<'info> {
    #[account(init, seeds = [b"fund_raising".as_ref(), signer.key().as_ref(), &anchor_lang::solana_program::hash::hash(token_metadata_uri.as_bytes()).to_bytes()], bump, payer = signer, space = 256)]
    pub fund_raising: Account<'info, FundRaising>,

    #[account(mut, seeds = [b"vault".as_ref(), fund_raising.key().as_ref()], bump)]
    pub vault: SystemAccount<'info>,

    #[account(init, seeds = [b"fame_status".as_ref(), fund_raising.key().as_ref()], bump, payer = signer, space = 8 + 34 + 32)]
    pub fame_status: Account<'info, FameStatus>,

    #[account(mut)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Buy<'info> {
    #[account(mut)]
    pub fund_raising: Account<'info, FundRaising>,

    #[account(mut, seeds = [b"vault".as_ref(), fund_raising.key().as_ref()], bump)]
    pub vault: SystemAccount<'info>,

    #[account(mut, seeds = [b"fame_status".as_ref(), fund_raising.key().as_ref()], bump)]
    pub fame_status: Account<'info, FameStatus>,

    #[account(init_if_needed, payer = signer, seeds = [b"share".as_ref(), fund_raising.key().as_ref(), signer.key().as_ref()], bump, space = 8 + 24 + 32 + 32)]
    pub share: Account<'info, Share>,
    #[account(mut)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Refund<'info> {
    #[account(mut)]
    pub fund_raising: Account<'info, FundRaising>,

    #[account(mut, seeds = [b"vault".as_ref(), fund_raising.key().as_ref()], bump)]
    pub vault: SystemAccount<'info>,

    #[account(mut, seeds = [b"fame_status".as_ref(), fund_raising.key().as_ref()], bump)]
    pub fame_status: Account<'info, FameStatus>,

    #[account(mut, seeds = [b"share".as_ref(), fund_raising.key().as_ref(), destination.key().as_ref()], bump)]
    pub share: Account<'info, Share>,
    /// CHECK: Safe
    #[account(mut)]
    pub destination: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts, Clone)]
pub struct CreateToken<'info> {
    #[account(mut)]
    pub fund_raising: Account<'info, FundRaising>,
    #[account(mut, seeds = [b"vault".as_ref(), fund_raising.key().as_ref()], bump)]
    pub vault: SystemAccount<'info>,
    #[account(mut, seeds = [b"fame_status".as_ref(), fund_raising.key().as_ref()], bump)]
    pub fame_status: Account<'info, FameStatus>,

    #[account(mut)]
    pub signer: Signer<'info>,
    /// CHECK: Safe
    #[account(mut)]
    pub metadata: UncheckedAccount<'info>,
    #[account(
        init_if_needed,
        seeds = [b"mint".as_ref(), fund_raising.key().as_ref()],
        bump,
        payer = signer,
        mint::decimals = fund_raising.token_decimal,
        mint::authority = mint,
    )]
    pub mint: Account<'info, Mint>,
    #[account(
        init_if_needed,
        payer = signer,
        associated_token::mint = mint,
        associated_token::authority = vault,
    )]
    pub vault_associated_token: Account<'info, TokenAccount>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
    /// CHECK: Safe
    #[account(mut)]
    pub fame_vault: AccountInfo<'info>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub metadata_program: Program<'info, Metadata>,
}

#[derive(Accounts)]
pub struct AssignToken<'info> {
    #[account(mut)]
    pub fund_raising: Account<'info, FundRaising>,
    #[account(mut, seeds = [b"vault".as_ref(), fund_raising.key().as_ref()], bump)]
    pub vault: SystemAccount<'info>,
    #[account(mut, seeds = [b"fame_status".as_ref(), fund_raising.key().as_ref()], bump)]
    pub fame_status: Account<'info, FameStatus>,
    #[account(mut)]
    pub signer: Signer<'info>,
    /// CHECK: Safe
    #[account(mut)]
    pub destination: AccountInfo<'info>,
    #[account(mut)]
    pub vault_associated_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub share: Account<'info, Share>,
    #[account(init_if_needed, payer = signer, associated_token::mint = mint, associated_token::authority = destination)]
    pub to_associated_token: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"mint".as_ref(), fund_raising.key().as_ref()], bump,)]
    pub mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}
#[derive(Accounts)]
pub struct BurnLpToken<'info> {
    #[account(mut)]
    pub fund_raising: Account<'info, FundRaising>,
    #[account(mut, seeds = [b"vault".as_ref(), fund_raising.key().as_ref()], bump)]
    pub vault: SystemAccount<'info>,
    #[account(mut)]
    pub user_lp_token_account: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"fame_status".as_ref(), fund_raising.key().as_ref()], bump)]
    pub fame_status: Account<'info, FameStatus>,
    /// CHECK: Safe
    pub serum_market: AccountInfo<'info>,
    /// CHECK: Safe
    pub amm_program: AccountInfo<'info>,
    #[account(
        mut,
        seeds = [
            amm_program.key.as_ref(),
            serum_market.key.as_ref(),
            b"lp_mint_associated_seed"
        ],
        bump,
        seeds::program = amm_program.key
    )]
    /// CHECK: Safe
    pub lp_mint: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
}
#[derive(Accounts)]
pub struct InitializeLp<'info> {
    #[account(mut)]
    pub fund_raising: Box<Account<'info, FundRaising>>,
    #[account(mut, seeds = [b"vault".as_ref(), fund_raising.key().as_ref()], bump)]
    pub vault: SystemAccount<'info>,
    #[account(mut, seeds = [b"fame_status".as_ref(), fund_raising.key().as_ref()], bump)]
    pub fame_status: Box<Account<'info, FameStatus>>,
    /// CHECK: Safe
    pub amm_program: AccountInfo<'info>,
    /// CHECK: Safe
    #[account(
        mut,
        seeds = [
            amm_program.key.as_ref(),
            serum_market.key.as_ref(),
            b"amm_associated_seed"],
        bump,
        seeds::program = amm_program.key
    )]
    pub amm: AccountInfo<'info>,
    /// CHECK: Safe
    #[account(
        seeds = [b"amm_config_account_seed"],
        bump,
        seeds::program = amm_program.key
    )]
    pub amm_config: AccountInfo<'info>,
    /// CHECK: Safe
    #[account(
        seeds = [b"amm authority"],
        bump,
        seeds::program = amm_program.key
    )]
    pub amm_authority: AccountInfo<'info>,
    /// CHECK: Safe
    #[account(
        mut,
        seeds = [
            amm_program.key.as_ref(),
            serum_market.key.as_ref(),
            b"open_order_associated_seed"],
        bump,
        seeds::program = amm_program.key
    )]
    pub amm_open_orders: AccountInfo<'info>,
    /// CHECK: Safe
    #[account(
        mut,
        seeds = [
            amm_program.key.as_ref(),
            serum_market.key.as_ref(),
            b"lp_mint_associated_seed"
        ],
        bump,
        seeds::program = amm_program.key
    )]
    pub lp_mint: AccountInfo<'info>,
    /// CHECK: Safe
    pub coin_mint: AccountInfo<'info>,
    /// CHECK: Safe
    pub pc_mint: AccountInfo<'info>,
    /// CHECK: Safe
    #[account(
        mut,
        seeds = [
            amm_program.key.as_ref(),
            serum_market.key.as_ref(),
            b"coin_vault_associated_seed"
        ],
        bump,
        seeds::program = amm_program.key
    )]
    pub pool_coin_token_account: AccountInfo<'info>,
    /// CHECK: Safe
    #[account(
        mut,
        seeds = [
            amm_program.key.as_ref(),
            serum_market.key.as_ref(),
            b"pc_vault_associated_seed"
        ],
        bump,
        seeds::program = amm_program.key
    )]
    pub pool_pc_token_account: AccountInfo<'info>,
    /// CHECK: Safe
    #[account(
        mut,
        seeds = [
            amm_program.key.as_ref(),
            serum_market.key.as_ref(),
            b"target_associated_seed"
        ],
        bump,
        seeds::program = amm_program.key
    )]
    pub amm_target_orders: AccountInfo<'info>,
    /// CHECK: Safe
    #[account(mut)]
    pub fee_destination: AccountInfo<'info>,
    /// CHECK: Safe
    #[account(
        mut,
        seeds = [
            amm_program.key.as_ref(),
            serum_market.key.as_ref(),
            b"temp_lp_token_associated_seed"
        ],
        bump,
        seeds::program = amm_program.key
    )]
    pub pool_temp_lp: AccountInfo<'info>,
    /// CHECK: Safe
    pub serum_program: AccountInfo<'info>,
    /// CHECK: Safe
    pub serum_market: AccountInfo<'info>,
    /// CHECK: Safe
    #[account(mut)]
    pub user_coin_token_account: AccountInfo<'info>,
    /// CHECK: Safe
    #[account(mut)]
    pub user_pc_token_account: AccountInfo<'info>,
    /// CHECK: Safe
    // #[account(mut)]
    #[account(mut)]
    pub user_lp_token_account: AccountInfo<'info>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[account]
pub struct FundRaising {
    creator: Pubkey,
    token_name: String,
    token_symbol: String,
    token_metadata_uri: String,
    token_decimal: u8,
    token_total_supply: u64,

    start_timestamp: i64,
    end_timestamp: i64,
    final_refund_timestamp: i64,
    lp_open_time_delay: u64,
    min_funds_threshold: u64,
    max_funds_cap: u64,
    min_funds_per_user: u64,
    max_funds_per_user: u64,
}

#[account]
pub struct FameStatus {
    fund_raising: Pubkey,
    current_funding_amount: u64,
    max_funding_amount: u64,
    funding_user_count: u32,
    refunding_user_count: u32,
    assigned_token_user_count: u32,
    token_created: bool,
    lp_created: bool,
}
#[account]
pub struct Share {
    fund_raising: Pubkey,
    owner: Pubkey,
    funding_amount: u64,
    share_amount: u64,
    has_refunded: bool,
    has_assigned_token: bool,
}

#[error_code]
pub enum FameError {
    #[msg("Not Started Yet")]
    NotStartedYet,
    #[msg("Has Ended")]
    HasEnded,
    #[msg("Not Ended Yet")]
    NotEndedYet,
    #[msg("Not Share Owner")]
    NotOwner,
    #[msg("Less Than Min Funds Per User")]
    LessThanMinFundsPerUser,
    #[msg("More Than Max Funds Per User")]
    MoreThanMaxFundsPerUser,
    #[msg("Already refunded")]
    AlreadyRefunded,
    #[msg("Missing holders")]
    MissingHolders,
    #[msg("Reached Min Funds Threshold")]
    ReachedMinFundsThreshold,
    #[msg("Not Reached Min Funds Threshold")]
    NotReachedMinFundsThreshold,
    #[msg("Already Created Token")]
    AlreadyCreatedToken,
    #[msg("Token Not Created Yet")]
    TokenNotCreatedYet,
    #[msg("Already Created Lp")]
    AlreadyCreatedLp,
    #[msg("Lp Not Created Yet")]
    LpNotCreatedYet,
    #[msg("Already Assigned Token")]
    AlreadyAssignedToken,
    #[msg("Associated Token Address Mismatch")]
    AssociatedTokenAddressMismatch,
    #[msg("Incorrect Token Vault")]
    IncorrectTokenVault,
    #[msg("Not Fame Vault")]
    NotFameVault,
    #[msg("Token Name Invalid")]
    TokenNameInvalid,
    #[msg("Duration Invalid")]
    DurationInvalid,
    #[msg("Funds Cap Invalid")]
    FundsCapInvalid,
    #[msg("Funds Threshold Invalid")]
    FundsThresholdInvalid,
}
