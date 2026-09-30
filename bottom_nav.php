<?php
// Shared bottom navigation bar with a floating scan button (FAB).
// Include it just before </body> on any page for logged-in users:
//     <?php include 'bottom_nav.php'; ?>
$current_page = basename($_SERVER['SCRIPT_NAME']);
$nav_home    = ($current_page === 'dashboard.php');
$nav_history = ($current_page === 'history.php');
$nav_scan    = in_array($current_page, ['scanner.php', 'analyze.php'], true);
?>
<style>
    /* Leave room so page content is never hidden behind the bar */
    body { padding-bottom: calc(90px + env(safe-area-inset-bottom, 0px)); }

    .bottom-nav {
        position: fixed;
        bottom: 0; left: 0; right: 0;
        height: calc(64px + env(safe-area-inset-bottom, 0px));
        padding-bottom: env(safe-area-inset-bottom, 0px);
        display: grid;
        grid-template-columns: 1fr 90px 1fr;
        align-items: center;
        background: var(--card-bg, #ffffff);
        border-top: 1px solid var(--border-color, #e2e8f0);
        box-shadow: 0 -4px 16px rgba(15, 23, 42, 0.06);
        z-index: 900;
    }
    .bn-item {
        display: flex; flex-direction: column; align-items: center; justify-content: center;
        gap: 3px; height: 64px;
        color: var(--text-muted, #64748b);
        text-decoration: none; font-size: 0.7rem; font-weight: 600;
    }
    .bn-item.active { color: var(--primary, #2563eb); }
    .bn-item:hover { color: var(--primary, #2563eb); }

    .bn-center {
        position: relative; height: 64px;
        display: flex; flex-direction: column; align-items: center; justify-content: flex-end;
    }
    .bn-fab {
        position: absolute; top: -28px;
        width: 62px; height: 62px; border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        background: var(--primary, #2563eb); color: #ffffff;
        border: 5px solid var(--bg-main, #f4f6f9);
        box-shadow: 0 6px 16px rgba(37, 99, 235, 0.4);
        transition: transform 0.15s, background 0.2s;
    }
    .bn-fab:hover { background: var(--primary-hover, #1d4ed8); transform: scale(1.05); }
    .bn-fab:active { transform: scale(0.95); }
    .bn-fab-label { padding-bottom: 9px; font-size: 0.7rem; font-weight: 600; color: var(--text-muted, #64748b); }
    .bn-center.active .bn-fab-label { color: var(--primary, #2563eb); }

    /* On wide screens, keep the bar phone-sized and centred */
    @media (min-width: 768px) {
        .bottom-nav {
            left: 50%; right: auto; width: 100%; max-width: 460px;
            transform: translateX(-50%);
            border: 1px solid var(--border-color, #e2e8f0); border-bottom: none;
            border-radius: 18px 18px 0 0;
        }
    }
</style>

<nav class="bottom-nav" aria-label="Main navigation">
    <a href="dashboard.php" class="bn-item <?php echo $nav_home ? 'active' : ''; ?>">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 10.5 12 3l9 7.5"/><path d="M5 9.5V21h14V9.5"/><path d="M10 21v-6h4v6"/></svg>
        <span>Home</span>
    </a>

    <div class="bn-center <?php echo $nav_scan ? 'active' : ''; ?>">
        <a href="scanner.php" class="bn-fab" aria-label="Scan QR code">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 8V6a2 2 0 0 1 2-2h2"/><path d="M16 4h2a2 2 0 0 1 2 2v2"/><path d="M20 16v2a2 2 0 0 1-2 2h-2"/><path d="M8 20H6a2 2 0 0 1-2-2v-2"/><path d="M4 12h16"/></svg>
        </a>
        <span class="bn-fab-label">Scan</span>
    </div>

    <a href="history.php" class="bn-item <?php echo $nav_history ? 'active' : ''; ?>">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
        <span>History</span>
    </a>
</nav>