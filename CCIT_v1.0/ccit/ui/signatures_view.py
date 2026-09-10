"""
CCIT Signatures Page
Displays the built-in threat signature database with filtering and custom rule addition.
"""

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QLabel, QLineEdit,
                                QPushButton, QTableWidget, QTableWidgetItem,
                                QVBoxLayout, QWidget)

from modules.signature_matcher import SignatureMatcher
from ui.theme import theme_manager


class SignaturesPage(QWidget):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._matcher = SignatureMatcher()
        self._all_rules = self._matcher.list_rules()
        self._setup_ui()
        self._populate_table(self._all_rules)

    def _setup_ui(self) -> None:
        p = theme_manager.palette
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(14)

        title = QLabel("[ ≡ ]  THREAT SIGNATURE DATABASE")
        title.setStyleSheet(
            f"color: {p.accent_primary}; font-size: 16px; font-weight: bold; letter-spacing: 3px;"
        )
        sub = QLabel(f"Built-in signature rules  ·  {len(self._all_rules)} rules loaded  ·  Custom YARA-like engine")
        sub.setStyleSheet(f"color: {p.text_secondary}; font-size: 10px;")
        root.addWidget(title)
        root.addWidget(sub)

        filter_row = QHBoxLayout()
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search rules…")
        self._search_input.textChanged.connect(self._apply_filter)
        self._cat_filter = QComboBox()
        self._cat_filter.addItem("All Categories")
        cats = sorted({r["category"] for r in self._all_rules})
        self._cat_filter.addItems(cats)
        self._cat_filter.currentTextChanged.connect(self._apply_filter)
        self._sev_filter = QComboBox()
        self._sev_filter.addItem("All Severities")
        self._sev_filter.addItems(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self._sev_filter.currentTextChanged.connect(self._apply_filter)
        self._refresh_btn = QPushButton("REFRESH")
        self._refresh_btn.setFixedWidth(80)
        self._refresh_btn.clicked.connect(lambda: self._apply_filter())

        filter_row.addWidget(QLabel("FILTER:"))
        filter_row.addWidget(self._search_input, 2)
        filter_row.addWidget(self._cat_filter, 1)
        filter_row.addWidget(self._sev_filter, 1)
        filter_row.addWidget(self._refresh_btn)
        root.addLayout(filter_row)

        self._count_label = QLabel(f"Showing {len(self._all_rules)} of {len(self._all_rules)} rules")
        self._count_label.setStyleSheet(f"color: {p.text_secondary}; font-size: 10px;")
        root.addWidget(self._count_label)

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["Rule ID", "Name", "Category", "Severity", "Description"])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setSortingEnabled(True)
        root.addWidget(self._table, 1)

    def _apply_filter(self) -> None:
        search = self._search_input.text().lower()
        cat = self._cat_filter.currentText()
        sev = self._sev_filter.currentText()

        filtered = []
        for rule in self._all_rules:
            if search and search not in rule["name"].lower() and search not in rule["description"].lower():
                continue
            if cat != "All Categories" and rule["category"] != cat:
                continue
            if sev != "All Severities" and rule["severity"] != sev:
                continue
            filtered.append(rule)

        self._populate_table(filtered)
        total = len(self._all_rules)
        self._count_label.setText(f"Showing {len(filtered)} of {total} rules")

    def _populate_table(self, rules: list[dict]) -> None:
        self._table.setRowCount(0)
        sev_colors = {
            "CRITICAL": "#FF0055",
            "HIGH":     "#FF6600",
            "MEDIUM":   "#FFAA00",
            "LOW":      "#AAFF00",
            "INFO":     "#00AAFF",
        }
        for rule in rules:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(rule["id"]))
            self._table.setItem(row, 1, QTableWidgetItem(rule["name"]))
            self._table.setItem(row, 2, QTableWidgetItem(rule["category"]))
            sev_item = QTableWidgetItem(rule["severity"])
            color = sev_colors.get(rule["severity"], "#888888")
            from PySide6.QtGui import QColor
            sev_item.setForeground(QColor(color))
            self._table.setItem(row, 3, sev_item)
            self._table.setItem(row, 4, QTableWidgetItem(rule["description"]))

    def refresh(self) -> None:
        self._apply_filter()
