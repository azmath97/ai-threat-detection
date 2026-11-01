"""Style sheets for the dashboards. Matte surfaces on a warm paper background, hairline borders, a serif display face for
headings and numbers, a deep green primary with a brass accent. No external fonts or assets are loaded."""

SERIF = '"Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif'
SANS = '"Segoe UI Variable", "Segoe UI", "Helvetica Neue", Arial, system-ui, sans-serif'

BASE_CSS = """
<style>
  :root { --bg:#F3F1EC; --card:#FFFFFF; --text:#17212B; --muted:#5E6B75; --faint:#8B969E; --line:#E7E3DA; --line-2:#D9D4C8;
          --green:#1E6F5C; --green-d:#154F42; --green-bg:#E4F0EC; --brass:#B08A3E; --brass-bg:#F6EEDC;
          --amber:#7E5A07; --amber-bg:#FAF0D4; --orange:#9A4A12; --orange-bg:#FAE6D6; --red:#A6302A; --red-bg:#F8E1DE;
          --blue:#2B5A78; --blue-bg:#E2ECF2; --ink:#10231F; --radius:12px;
          --serif:__SERIF__; --sans:__SANS__;
          --shadow:0 1px 2px rgba(23,33,43,.06), 0 6px 18px -8px rgba(23,33,43,.12); }
  html, body, [class*="css"], .stApp { font-family: var(--sans); color: var(--text); }
  .stApp { background: var(--bg); }
  #MainMenu, footer, [data-testid="stToolbar"], [data-testid="stDecoration"], [data-testid="stStatusWidget"] { display:none !important; }
  header[data-testid="stHeader"] { background: transparent; height: 0; }
  .block-container { padding-top: 1.8rem; padding-bottom: 2.5rem; max-width: 1240px; }
  ::selection { background: var(--green-bg); }
  *:focus-visible { outline: 2px solid var(--brass) !important; outline-offset: 2px; }

  @keyframes rise { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: none; } }
  @keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(30,111,92,.45); } 70% { box-shadow: 0 0 0 7px rgba(30,111,92,0); } 100% { box-shadow: 0 0 0 0 rgba(30,111,92,0); } }
  @media (prefers-reduced-motion: reduce) { * { animation: none !important; transition: none !important; } }

  /* headings: serif display face, ruled section titles */
  h1, h2, h3 { color: var(--text); letter-spacing: 0; }
  div[data-testid="stMarkdownContainer"] h1 { font-family: var(--serif); font-size: 1.95rem !important; font-weight: 600 !important; line-height: 1.2 !important;
      margin: 0 0 .2rem 0 !important; padding: 0 !important; }
  div[data-testid="stMarkdownContainer"] h3 { display: flex; align-items: center; gap: .9rem; font-family: var(--serif); font-size: 1.15rem !important;
      font-weight: 600 !important; line-height: 1.3 !important; margin: 1.9rem 0 .8rem 0 !important; padding: 0 !important; }
  div[data-testid="stMarkdownContainer"] h3::after { content: ""; flex: 1; height: 1px; background: var(--line-2); }
  div[data-testid="stMarkdownContainer"] h1 a, div[data-testid="stMarkdownContainer"] h3 a { display: none !important; }
  .page-sub { color: var(--muted); font-size: .92rem; margin: 0 0 1.2rem 0; }

  /* sidebar */
  section[data-testid="stSidebar"] { background: #FBFAF7; border-right: 1px solid var(--line); }
  section[data-testid="stSidebar"] > div { padding-top: 1.1rem; }
  .brand { display: flex; align-items: center; gap: .7rem; padding: .1rem .35rem 1rem .35rem; }
  .brand-mark { width: 38px; height: 38px; border-radius: 10px; background: var(--ink); color: #E9D9AE; font-family: var(--serif); font-weight: 700;
      display: flex; align-items: center; justify-content: center; font-size: 1.25rem; box-shadow: inset 0 0 0 1.5px var(--brass); flex: none; }
  .org-name { font-family: var(--serif); font-weight: 700; color: var(--text); font-size: 1.08rem; line-height: 1.2; }
  .org-sub { color: var(--muted); font-size: .74rem; letter-spacing: .02em; }
  .nav-caption { color: var(--faint); font-size: .66rem; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; margin: 1.25rem 0 .5rem .6rem; }
  .user-card { display: flex; align-items: center; gap: .7rem; border-top: 1px dashed var(--line-2); padding-top: .9rem; margin-top: 1.3rem; }
  .avatar { width: 36px; height: 36px; border-radius: 50%; background: var(--brass-bg); color: #6B5320; font-weight: 700; font-size: .82rem;
      display: flex; align-items: center; justify-content: center; flex: none; box-shadow: inset 0 0 0 1px var(--brass); }
  .user-card .u-name { font-weight: 600; font-size: .86rem; line-height: 1.25; }
  .user-card .u-sub { color: var(--muted); font-size: .74rem; }
  section[data-testid="stSidebar"] .stButton > button { justify-content: flex-start; text-align: left; border: none; border-radius: 9px;
      background: transparent; color: var(--muted); font-weight: 600; padding: .5rem .8rem; box-shadow: none; min-height: 2.35rem; transition: background .15s, color .15s; }
  section[data-testid="stSidebar"] .stButton > button:hover { background: rgba(23,33,43,.05); color: var(--text); }
  section[data-testid="stSidebar"] .stButton > button[kind="primary"] { background: var(--green-bg); color: var(--green-d); font-weight: 700; box-shadow: inset 3px 0 0 var(--green); }
  section[data-testid="stSidebar"] .stButton > button[kind="primary"]:hover { background: #D8E9E3; }
  section[data-testid="stSidebar"] .stButton { margin-bottom: 0; }
  section[data-testid="stSidebar"] .stButton > button > div { justify-content: flex-start !important; width: 100%; gap: .6rem; }
  section[data-testid="stSidebar"] .stButton > button p { text-align: left !important; font-size: .9rem; }
  section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] { gap: .15rem; }

  /* controls */
  .stButton > button, .stDownloadButton > button, .stFormSubmitButton > button { border-radius: 10px; box-shadow: none; font-weight: 600;
      border: 1px solid var(--line-2); background: var(--card); color: var(--text); transition: border-color .15s, transform .15s, background .15s; }
  .stButton > button:hover, .stDownloadButton > button:hover { border-color: var(--text); color: var(--text); }
  .stButton > button:active { transform: translateY(1px); }
  .stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primaryFormSubmit"], .stDownloadButton > button[kind="primary"] {
      background: var(--green); border-color: var(--green); color: #fff; font-weight: 700; }
  .stButton > button[kind="primary"]:hover, .stFormSubmitButton > button[kind="primaryFormSubmit"]:hover { background: var(--green-d); border-color: var(--green-d); color: #fff; }
  div[data-testid="stTextInputRootElement"], div[data-testid="stNumberInputContainer"], .stSelectbox div[data-baseweb="select"] > div {
      border-radius: 10px; border: 1px solid var(--line-2) !important; background: #fff; }
  div[data-testid="stTextInputRootElement"]:focus-within, div[data-testid="stNumberInputContainer"]:focus-within,
  .stSelectbox div[data-baseweb="select"]:focus-within > div { border-color: var(--green) !important; }
  div[data-testid="stForm"] { border: 1px solid var(--line); border-radius: 16px; padding: 1.5rem; background: var(--card); box-shadow: var(--shadow); }
  div[data-testid="stWidgetLabel"] p { font-size: .84rem; font-weight: 600; color: var(--muted); }

  /* data grid (static HTML: no client-side export) */
  .grid-wrap { background: var(--card); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); max-height: 460px;
      overflow: auto; margin-bottom: .9rem; scrollbar-width: thin; scrollbar-color: var(--line-2) transparent; }
  table.grid { width: 100%; border-collapse: collapse; font-size: .875rem; font-variant-numeric: tabular-nums; }
  table.grid th { position: sticky; top: 0; text-align: left; background: #FAF8F3; color: var(--muted); font-weight: 700; font-size: .68rem;
      letter-spacing: .09em; text-transform: uppercase; padding: .75rem 1rem; white-space: nowrap; border-bottom: 1px solid var(--line-2); }
  table.grid td { padding: .72rem 1rem; border-bottom: 1px solid var(--line); }
  table.grid tbody tr { transition: background .12s; }
  table.grid tbody tr:hover td { background: #FBFAF6; }
  table.grid tr:last-child td { border-bottom: none; }
  table.grid td.empty { color: var(--muted); text-align: center; padding: 1.8rem; }
  .pill { display: inline-flex; align-items: center; gap: .4rem; border-radius: 999px; padding: .12rem .65rem; font-size: .76rem; font-weight: 700; white-space: nowrap; }
  .pill i { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
  .pill-ok { color: var(--green-d); background: var(--green-bg); }
  .pill-bad { color: var(--red); background: var(--red-bg); }
  .pill-warn { color: var(--amber); background: var(--amber-bg); }
  .pill-high { color: var(--orange); background: var(--orange-bg); }

  /* activity feed */
  .feed { background: var(--card); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); padding: .4rem 1.2rem; margin-bottom: .9rem; }
  .feed .f-row { position: relative; display: flex; justify-content: space-between; gap: 1rem; padding: .85rem 0 .85rem 1.6rem; border-bottom: 1px dashed var(--line-2); }
  .feed .f-row:last-child { border-bottom: none; }
  .feed .f-row::before { content: ""; position: absolute; left: .15rem; top: 1.3rem; width: 9px; height: 9px; border-radius: 50%; background: var(--green); box-shadow: 0 0 0 4px var(--green-bg); }
  .feed .f-row.bad::before { background: #C2403A; box-shadow: 0 0 0 4px var(--red-bg); }
  .feed .f-row.warn::before { background: var(--brass); box-shadow: 0 0 0 4px var(--brass-bg); }
  .feed .f-title { font-weight: 600; font-size: .9rem; }
  .feed .f-sub { color: var(--muted); font-size: .78rem; margin-top: .1rem; }
  .feed .f-time { color: var(--muted); font-size: .78rem; white-space: nowrap; font-variant-numeric: tabular-nums; }

  /* notices */
  .notice { border-radius: 10px; padding: .8rem 1rem; margin: .6rem 0; font-size: .9rem; line-height: 1.55; border: 1px solid transparent; }
  .notice.ok { background: var(--green-bg); color: var(--green-d); border-color: #CFE3DB; }
  .notice.warn { background: var(--amber-bg); color: var(--amber); border-color: #EBDDB1; }
  .notice.error { background: var(--red-bg); color: var(--red); border-color: #EFC9C5; }
  .notice.info { background: var(--blue-bg); color: var(--blue); border-color: #C9DCE8; }

  /* key / value table */
  table.kv { width: 100%; border-collapse: separate; border-spacing: 0; font-size: .9rem; margin-bottom: .7rem; background: var(--card);
      border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden; }
  table.kv th { text-align: left; width: 220px; color: var(--muted); font-weight: 600; font-size: .78rem; padding: .7rem 1rem; border-bottom: 1px solid var(--line); background: #FAF8F3; }
  table.kv td { padding: .7rem 1rem; border-bottom: 1px solid var(--line); }
  table.kv tr:last-child th, table.kv tr:last-child td { border-bottom: none; }

  /* banner: matte, with a quiet dot grid */
  .hero { position: relative; border-radius: 16px; padding: 1.9rem 2.1rem; color: #fff; margin: .2rem 0 1.3rem 0; box-shadow: var(--shadow); overflow: hidden;
      background-color: var(--ink); background-image: radial-gradient(rgba(233,217,174,.16) 1px, transparent 1.4px); background-size: 16px 16px;
      animation: rise .5s ease both; }
  .hero::after { content: ""; position: absolute; right: -60px; top: -60px; width: 220px; height: 220px; border-radius: 50%; border: 1.5px solid rgba(176,138,62,.5); }
  .hero::before { content: ""; position: absolute; right: -20px; top: -20px; width: 140px; height: 140px; border-radius: 50%; border: 1.5px solid rgba(176,138,62,.28); }
  .hero .h-eyebrow { color: #D9BE7A; font-size: .7rem; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; }
  .hero .h-title { font-family: var(--serif); font-size: 1.85rem; font-weight: 600; line-height: 1.25; margin: .45rem 0 .5rem 0; color: #fff; }
  .hero .h-text { color: #C5D0CC; font-size: .93rem; max-width: 640px; line-height: 1.6; position: relative; z-index: 1; }
  .hero .h-chips { margin-top: 1.1rem; display: flex; gap: .5rem; flex-wrap: wrap; position: relative; z-index: 1; }
  .hero .h-chip { border: 1px solid rgba(233,217,174,.32); border-radius: 999px; padding: .2rem .8rem; font-size: .76rem; color: #EFE7CF; }
  .hero.alert { background-color: #2A1616; background-image: radial-gradient(rgba(255,170,150,.14) 1px, transparent 1.4px); }
  .hero.alert .h-eyebrow { color: #F2A28E; }

  /* login */
  .login-brand { display: flex; align-items: center; gap: .8rem; margin-bottom: 1.3rem; }
  .login-title { font-family: var(--serif); font-size: 1.5rem; font-weight: 700; color: var(--text); line-height: 1.2; }
  .login-sub { color: var(--muted); font-size: .88rem; }
  .fine-print { color: var(--muted); font-size: .76rem; margin-top: 1rem; line-height: 1.5; }
  .sim-banner { background: var(--amber-bg); color: var(--amber); padding: .8rem 1.1rem; border-radius: 10px; font-weight: 700; font-size: .86rem;
      margin-bottom: 1.1rem; border: 1px solid #EBDDB1; }

  /* responsive */
  @media (max-width: 1100px) {
    div[data-testid="stHorizontalBlock"] { flex-wrap: wrap; }
    div[data-testid="stHorizontalBlock"] > div[data-testid="stColumn"] { min-width: min(100%, 320px); }
  }
  @media (max-width: 900px) {
    .block-container { padding: 1.1rem 1rem 2rem 1rem; }
    div[data-testid="stMarkdownContainer"] h1 { font-size: 1.55rem !important; }
    .hero { padding: 1.4rem 1.3rem; }
    .hero .h-title { font-size: 1.4rem; }
    table.kv { table-layout: fixed; }
    table.kv th { width: 38%; }
    table.kv td { overflow-wrap: anywhere; }
    .feed .f-row { flex-direction: column; gap: .2rem; }
  }
  @media (max-width: 560px) {
    table.grid th, table.grid td { padding: .6rem .7rem; }
    .hero::before, .hero::after { display: none; }
  }
</style>
""".replace("__SERIF__", SERIF).replace("__SANS__", SANS)

SOC_CSS = """
<style>
  .block-container { max-width: 1480px; padding-top: 1.4rem; }
  @media (min-width: 900px) { section[data-testid="stSidebar"] { width: 262px !important; min-width: 262px !important; } }
  section[data-testid="stSidebar"] .stButton { position: relative; z-index: 3; }
  section[data-testid="stSidebar"] > div { padding-top: .6rem; }
  section[data-testid="stSidebar"] .stButton > button:focus:not(:active):not([kind="primary"]) { background: transparent; box-shadow: none; }

  .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1rem; margin: .3rem 0 1rem 0; }
  .kpi { display: flex; justify-content: space-between; align-items: center; gap: .6rem; background: var(--card); border: 1px solid var(--line);
      border-radius: var(--radius); box-shadow: var(--shadow); padding: 1.15rem 1.3rem; min-height: 112px; animation: rise .5s ease both;
      transition: transform .18s ease, border-color .18s ease; }
  .kpi:hover { transform: translateY(-2px); border-color: var(--line-2); }
  .kpi:nth-child(2) { animation-delay: .04s; } .kpi:nth-child(3) { animation-delay: .08s; } .kpi:nth-child(4) { animation-delay: .12s; }
  .kpi:nth-child(5) { animation-delay: .16s; } .kpi:nth-child(6) { animation-delay: .2s; }
  .kpi .k-text { min-width: 0; }
  .kpi .k-label { color: var(--muted); font-size: .68rem; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; }
  .kpi .k-value { font-family: var(--serif); color: var(--text); font-size: 2.15rem; font-weight: 600; line-height: 1.2; margin: .2rem 0 .1rem 0;
      word-break: normal; font-variant-numeric: tabular-nums; }
  .kpi .k-value.long { font-size: 1.2rem; line-height: 1.8; }
  .kpi .k-sub { color: var(--muted); font-size: .76rem; }
  .kpi .k-visual { flex: none; }
  .kpi .k-icon { width: 46px; height: 46px; border-radius: 50%; display: flex; align-items: center; justify-content: center;
      background: var(--green-bg); color: var(--green-d); }
  .kpi .k-icon svg { width: 22px; height: 22px; stroke: currentColor; fill: none; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
  .kpi .spark { width: 96px; height: 44px; }
  .kpi.warn .k-icon { background: var(--amber-bg); color: var(--amber); }
  .kpi.alert .k-icon { background: var(--red-bg); color: var(--red); }
  .kpi.alert .k-value { color: var(--red); }
  .kpi.warn .k-value { color: var(--orange); }

  .meter { display: grid; grid-template-columns: 150px 1fr; gap: 1.4rem; align-items: center; background: var(--card); border: 1px solid var(--line);
      border-radius: var(--radius); box-shadow: var(--shadow); padding: 1.3rem 1.5rem; }
  .meter .m-ring { position: relative; width: 140px; height: 140px; }
  .meter .m-ring svg { width: 140px; height: 140px; transform: rotate(-90deg); }
  .meter .m-ring .track { stroke: #EFEBE2; }
  .meter .m-ring .arc { transition: stroke-dashoffset .8s ease; }
  .meter .m-score { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .meter .m-score b { font-family: var(--serif); font-size: 2.3rem; font-weight: 600; line-height: 1; font-variant-numeric: tabular-nums; }
  .meter .m-of { color: var(--muted); font-size: .72rem; margin-top: .15rem; }
  .meter .m-head { display: flex; align-items: center; gap: .8rem; margin-bottom: .9rem; }
  .meter .m-title { font-size: .68rem; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); }
  .sev { font-size: .74rem; font-weight: 700; padding: .18rem .7rem; border-radius: 999px; }
  .sev-normal { color: var(--green-d); background: var(--green-bg); }
  .sev-suspicious { color: var(--amber); background: var(--amber-bg); }
  .sev-high_risk { color: var(--orange); background: var(--orange-bg); }
  .sev-critical { color: var(--red); background: var(--red-bg); }
  .m-bar { position: relative; display: flex; height: 10px; border-radius: 999px; }
  .m-bar .band { height: 100%; border-right: 2px solid #fff; box-sizing: border-box; }
  .m-bar .band:first-child { border-radius: 999px 0 0 999px; }
  .m-bar .band:nth-last-child(2) { border-radius: 0 999px 999px 0; border-right: none; }
  .m-bar .marker { position: absolute; top: -6px; width: 6px; height: 22px; border-radius: 3px; background: var(--text); border: 2px solid #fff; box-sizing: content-box; }
  .m-scale { position: relative; height: 22px; font-size: .72rem; color: var(--muted); margin-top: .5rem; }
  .m-scale span { position: absolute; transform: translateX(-50%); }
  .m-legend { font-size: .74rem; color: var(--muted); margin-top: .2rem; }

  .stages { display: flex; background: var(--card); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow);
      margin: .3rem 0 1rem 0; overflow-x: auto; scrollbar-width: thin; }
  .stages .st { flex: 1 0 118px; padding: .85rem .8rem; border-right: 1px dashed var(--line-2); min-width: 0; }
  .stages .st:last-child { border-right: none; }
  .stages .st .s-name { font-size: .76rem; color: var(--muted); font-weight: 700; }
  .stages .st .s-info { font-size: .72rem; color: var(--muted); margin-top: .25rem; min-height: 1.9em; }
  .stages .st.reached { background: var(--green-bg); }
  .stages .st.reached .s-name { color: var(--green-d); }
  .stages .st.current { background: var(--red-bg); box-shadow: inset 0 -3px 0 #C2403A; }
  .stages .st.current .s-name { color: var(--red); }

  .live-note { color: var(--muted); font-size: .76rem; margin-bottom: .6rem; }
  .live-dot { display: inline-block; width: 8px; height: 8px; background: var(--green); border-radius: 50%; margin-right: 7px; animation: pulse 2s infinite; }
  .tag { font-size: .7rem; background: #F4F1E9; padding: .1rem .5rem; color: var(--muted); border-radius: 999px; }
  div[data-testid="stPlotlyChart"] { background: var(--card); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden; padding: .4rem; }

  @media (max-width: 900px) {
    .meter { grid-template-columns: 1fr; justify-items: center; text-align: center; }
    .meter .m-body { width: 100%; }
    .kpi { min-height: 96px; }
    .kpi .k-value { font-size: 1.8rem; }
  }
</style>
"""
