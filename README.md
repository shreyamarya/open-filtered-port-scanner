# 🔎 Open & Filtered Port Scanner (Python)

This is a fast, multi-threaded port scanner built in Python that scans TCP or UDP ports and displays only **open** and **open|filtered** ports with banner grabbing.

## ⚙️ Features

* Supports both **TCP** and **UDP** scans
* Multi-threaded for fast performance
* Banner grabbing (GET request on open TCP ports)
* Ignores closed ports to reduce clutter
* Summary report at the end of each scan
* Optional output saving to a file

## 🚀 Usage

```bash
python3 scanner.py <target> [--ports PORTS] [--udp] [--workers N] [--save output.txt]
```

### Examples

* Scan top 1024 TCP ports:

  ```bash
  python3 scanner.py 192.168.1.1
  ```

* Scan specific ports with 100 threads:

  ```bash
  python3 scanner.py example.com --ports 21,22,80,443 --workers 100
  ```

* UDP scan:

  ```bash
  python3 scanner.py 10.0.0.5 --udp
  ```

* Save results to a file:

  ```bash
  python3 scanner.py 192.168.0.1 --save result.txt
  ```

## 📝 Output Summary

At the end of the scan, the tool provides:

* Total number of ports scanned
* All **open** and **open|filtered** ports with:

  * Port number
  * Common service name
  * Banner (if available)

## ⚠️ Notes

* Closed ports are not displayed.
* UDP scans may show many **open|filtered** results due to no response behavior.
* Use responsibly and only on systems you own or are authorized to scan.

## 💡 System Recommendations

| System Type     | Recommended Max Threads |
| --------------- | ----------------------- |
| Low-end PC      | 50–100                  |
| Mid-range PC    | 100–500                 |
| High-end/server | 500–2000+               |

## 📜 License

MIT License
