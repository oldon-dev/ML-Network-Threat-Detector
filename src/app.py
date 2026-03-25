try:
    from qt_desktop_app import main
except ImportError as exc:
    raise SystemExit(
        "PySide6 is required for the desktop UI. Install it with `pip install PySide6`."
    ) from exc


if __name__ == "__main__":
    main()
