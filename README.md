# sockmon
sockmon is a tool for monitoring TCP/UDP connections on Linux. It retrieves connection information via netlink and displays it periodically. The displayed items can be customized.

## Screenshots
### Main view
![Main view](https://hiroa-ki.github.io/screenshots/sockmon/0.2.0-0001.png)  
Peer addresses have been redacted.

### Field configuration
![Field configuration](https://hiroa-ki.github.io/screenshots/sockmon/0.2.0-0002.png)  
![Field configuration](https://hiroa-ki.github.io/screenshots/sockmon/0.2.0-0003.png)

## Requirements
- Meson
- ncurses (development headers)

## Build
```bash
meson setup build
meson compile -C build
```

## Run
```bash
./build/src/sockmon
```

- Press `q` to Quit.
- Press `f` to customize the displayed fields.

## License
GPL-2.0-only

Copyright (C) 2026 Hiroaki Shimoda
