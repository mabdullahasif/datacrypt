"""
DataCrypt GUI — Dark Theme Stylesheet
Premium dark glassmorphism theme with gradient accents.
"""

# ─── Color Palette ──────────────────────────────────────────────────────
COLORS = {
    "bg_darkest":    "#0d1017",
    "bg_dark":       "#131820",
    "bg_card":       "#1a2233",
    "bg_card_hover": "#1f2b40",
    "bg_input":      "#0f1620",
    "bg_elevated":   "#243044",
    "border":        "#2a3a52",
    "border_focus":  "#4a8eff",
    "text_primary":  "#e6edf3",
    "text_secondary":"#8b949e",
    "text_muted":    "#484f58",
    "accent_blue":   "#4a8eff",
    "accent_purple": "#8957e5",
    "accent_cyan":   "#39d2c0",
    "success":       "#3fb950",
    "warning":       "#d29922",
    "danger":        "#f85149",
    "danger_hover":  "#ff6e6a",
}

# ─── Constants ──────────────────────────────────────────────────────────
FONT_FAMILY = "'Segoe UI', 'SF Pro Display', 'Helvetica Neue', Arial, sans-serif"
BORDER_RADIUS = "8px"
BORDER_RADIUS_SM = "6px"
BORDER_RADIUS_LG = "12px"


def get_stylesheet() -> str:
    """Returns the complete QSS stylesheet for the DataCrypt GUI."""
    c = COLORS
    return f"""
    /* ═══════════════ Global ═══════════════ */
    QWidget {{
        font-family: {FONT_FAMILY};
        font-size: 13px;
        color: {c["text_primary"]};
        background-color: {c["bg_darkest"]};
    }}

    QMainWindow {{
        background-color: {c["bg_darkest"]};
    }}

    /* ═══════════════ Cards (GroupBox) ═══════════════ */
    QGroupBox {{
        background-color: {c["bg_card"]};
        border: 1px solid {c["border"]};
        border-radius: {BORDER_RADIUS_LG};
        margin-top: 8px;
        padding: 20px 16px 16px 16px;
        font-weight: 600;
        font-size: 13px;
    }}

    QGroupBox::title {{
        subcontrol-origin: margin;
        subcontrol-position: top left;
        padding: 4px 14px;
        background-color: {c["bg_elevated"]};
        border: 1px solid {c["border"]};
        border-radius: {BORDER_RADIUS_SM};
        color: {c["accent_cyan"]};
        font-weight: 700;
        font-size: 12px;
        letter-spacing: 0.5px;
    }}

    /* ═══════════════ Buttons ═══════════════ */
    QPushButton {{
        background-color: {c["bg_elevated"]};
        color: {c["text_primary"]};
        border: 1px solid {c["border"]};
        border-radius: {BORDER_RADIUS};
        padding: 8px 18px;
        font-weight: 600;
        font-size: 13px;
        min-height: 20px;
    }}

    QPushButton:hover {{
        background-color: {c["bg_card_hover"]};
        border-color: {c["accent_blue"]};
    }}

    QPushButton:pressed {{
        background-color: {c["bg_dark"]};
    }}

    QPushButton:disabled {{
        background-color: {c["bg_dark"]};
        color: {c["text_muted"]};
        border-color: {c["bg_card"]};
    }}

    QPushButton#btn_encrypt {{
        background-color: #1a5c2e;
        border-color: #2a7a3e;
        color: #c8f7d5;
        font-size: 14px;
        padding: 10px 28px;
        min-height: 24px;
    }}
    QPushButton#btn_encrypt:hover {{
        background-color: #1f7035;
        border-color: {c["success"]};
    }}

    QPushButton#btn_decrypt {{
        background-color: #1a4080;
        border-color: #2a60a0;
        color: #c0d8f7;
        font-size: 14px;
        padding: 10px 28px;
        min-height: 24px;
    }}
    QPushButton#btn_decrypt:hover {{
        background-color: #1f4f99;
        border-color: {c["accent_blue"]};
    }}

    QPushButton#btn_cancel {{
        background-color: #5c1a1a;
        border-color: #802a2a;
        color: #f7c0c0;
    }}
    QPushButton#btn_cancel:hover {{
        background-color: #702020;
        border-color: {c["danger"]};
    }}

    QPushButton#btn_generate {{
        background-color: #3d1a6e;
        border-color: #5a2d99;
        color: #d4b8f0;
    }}
    QPushButton#btn_generate:hover {{
        background-color: #4a2080;
        border-color: {c["accent_purple"]};
    }}

    QPushButton#btn_copy {{
        padding: 8px 14px;
        font-size: 12px;
    }}

    /* ═══════════════ Inputs ═══════════════ */
    QLineEdit {{
        background-color: {c["bg_input"]};
        color: {c["text_primary"]};
        border: 1px solid {c["border"]};
        border-radius: {BORDER_RADIUS_SM};
        padding: 8px 12px;
        font-size: 13px;
        selection-background-color: {c["accent_blue"]};
    }}

    QLineEdit:focus {{
        border-color: {c["accent_blue"]};
        background-color: #111a28;
    }}

    QLineEdit:disabled {{
        background-color: {c["bg_dark"]};
        color: {c["text_muted"]};
    }}

    QLineEdit[readOnly="true"] {{
        background-color: {c["bg_dark"]};
    }}

    /* ═══════════════ ComboBox ═══════════════ */
    QComboBox {{
        background-color: {c["bg_input"]};
        color: {c["text_primary"]};
        border: 1px solid {c["border"]};
        border-radius: {BORDER_RADIUS_SM};
        padding: 8px 12px;
        font-size: 13px;
        min-width: 140px;
    }}

    QComboBox:hover {{
        border-color: {c["accent_blue"]};
    }}

    QComboBox::drop-down {{
        subcontrol-origin: padding;
        subcontrol-position: center right;
        width: 28px;
        border: none;
    }}

    QComboBox::down-arrow {{
        image: none;
        border-left: 5px solid transparent;
        border-right: 5px solid transparent;
        border-top: 6px solid {c["text_secondary"]};
        margin-right: 8px;
    }}

    QComboBox QAbstractItemView {{
        background-color: {c["bg_card"]};
        color: {c["text_primary"]};
        border: 1px solid {c["border"]};
        border-radius: {BORDER_RADIUS_SM};
        selection-background-color: {c["accent_blue"]};
        outline: none;
        padding: 4px;
    }}

    /* ═══════════════ SpinBox ═══════════════ */
    QSpinBox {{
        background-color: {c["bg_input"]};
        color: {c["text_primary"]};
        border: 1px solid {c["border"]};
        border-radius: {BORDER_RADIUS_SM};
        padding: 6px 10px;
        font-size: 13px;
    }}

    QSpinBox:focus {{
        border-color: {c["accent_blue"]};
    }}

    QSpinBox::up-button, QSpinBox::down-button {{
        background-color: {c["bg_elevated"]};
        border: none;
        width: 20px;
    }}

    /* ═══════════════ CheckBox ═══════════════ */
    QCheckBox {{
        spacing: 8px;
        font-size: 12px;
        color: {c["text_secondary"]};
    }}

    QCheckBox::indicator {{
        width: 16px;
        height: 16px;
        border-radius: 4px;
        border: 1px solid {c["border"]};
        background-color: {c["bg_input"]};
    }}

    QCheckBox::indicator:checked {{
        background-color: {c["accent_blue"]};
        border-color: {c["accent_blue"]};
    }}

    QCheckBox::indicator:hover {{
        border-color: {c["accent_blue"]};
    }}

    /* ═══════════════ Radio Button ═══════════════ */
    QRadioButton {{
        spacing: 8px;
        font-size: 13px;
        color: {c["text_secondary"]};
    }}

    QRadioButton::indicator {{
        width: 16px;
        height: 16px;
        border-radius: 9px;
        border: 2px solid {c["border"]};
        background-color: {c["bg_input"]};
    }}

    QRadioButton::indicator:checked {{
        background-color: {c["accent_blue"]};
        border-color: {c["accent_blue"]};
    }}

    /* ═══════════════ Progress Bar ═══════════════ */
    QProgressBar {{
        background-color: {c["bg_input"]};
        border: 1px solid {c["border"]};
        border-radius: {BORDER_RADIUS};
        text-align: center;
        font-weight: 600;
        font-size: 12px;
        color: {c["text_primary"]};
        min-height: 22px;
    }}

    QProgressBar::chunk {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
            stop:0 {c["accent_blue"]}, stop:1 {c["accent_cyan"]});
        border-radius: 7px;
    }}

    /* ═══════════════ Labels ═══════════════ */
    QLabel {{
        color: {c["text_primary"]};
        background-color: transparent;
        font-size: 13px;
        border: none;
    }}

    QLabel#label_title {{
        font-size: 22px;
        font-weight: 800;
        color: {c["accent_cyan"]};
        letter-spacing: 1px;
    }}

    QLabel#label_subtitle {{
        font-size: 12px;
        color: {c["text_secondary"]};
    }}

    QLabel#label_status {{
        font-size: 12px;
        padding: 6px 12px;
        border-radius: {BORDER_RADIUS_SM};
        background-color: {c["bg_card"]};
        border: 1px solid {c["border"]};
    }}

    QLabel#label_strength {{
        font-size: 12px;
        font-weight: 600;
    }}

    QLabel#label_eta {{
        font-size: 12px;
        color: {c["text_secondary"]};
    }}

    QLabel#label_fileinfo {{
        font-size: 12px;
        color: {c["text_secondary"]};
    }}

    QLabel#label_drop_zone {{
        background-color: {c["bg_input"]};
        border: 2px dashed {c["border"]};
        border-radius: {BORDER_RADIUS_LG};
        padding: 24px;
        font-size: 13px;
        color: {c["text_muted"]};
        min-height: 48px;
    }}

    QLabel#label_drop_zone[dragActive="true"] {{
        border-color: {c["accent_cyan"]};
        background-color: #0d1f2d;
        color: {c["accent_cyan"]};
    }}

    /* ═══════════════ Scroll Area ═══════════════ */
    QScrollArea {{
        border: none;
        background-color: transparent;
    }}

    QScrollBar:vertical {{
        background-color: {c["bg_dark"]};
        width: 10px;
        border-radius: 5px;
        margin: 0;
    }}

    QScrollBar::handle:vertical {{
        background-color: {c["bg_elevated"]};
        border-radius: 5px;
        min-height: 30px;
    }}

    QScrollBar::handle:vertical:hover {{
        background-color: {c["border"]};
    }}

    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0;
    }}

    /* ═══════════════ Status Bar ═══════════════ */
    QStatusBar {{
        background-color: {c["bg_dark"]};
        border-top: 1px solid {c["border"]};
        color: {c["text_secondary"]};
        font-size: 12px;
        padding: 4px 8px;
    }}

    /* ═══════════════ ToolTip ═══════════════ */
    QToolTip {{
        background-color: {c["bg_elevated"]};
        color: {c["text_primary"]};
        border: 1px solid {c["border"]};
        border-radius: 4px;
        padding: 6px 10px;
        font-size: 12px;
    }}

    /* ═══════════════ Separator ═══════════════ */
    QFrame[frameShape="4"] {{
        color: {c["border"]};
        max-height: 1px;
    }}
    """
