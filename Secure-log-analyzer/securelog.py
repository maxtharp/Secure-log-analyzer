import argparse
import re
from collections import Counter


LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<request>[^"]*)" '
    r'(?P<status>\d{3})(?: (?P<size>\S+))?(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?$'
)

FAILED_LOGIN_PATH_PATTERN = re.compile(r"(login|signin|auth)", re.IGNORECASE)


def parse_log(file_path):
    entries = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            match = LOG_PATTERN.match(line)
            if not match:
                continue

            payload = match.groupdict()
            request_parts = payload["request"].split()
            method = request_parts[0] if len(request_parts) >= 1 else "-"
            path = request_parts[1] if len(request_parts) >= 2 else "-"
            protocol = request_parts[2] if len(request_parts) >= 3 else "-"

            raw_size = payload.get("size")
            if raw_size in {None, "-"}:
                size = 0
            else:
                try:
                    size = int(raw_size)
                except ValueError:
                    size = 0

            entries.append(
                {
                    "ip": payload["ip"],
                    "timestamp": payload["timestamp"],
                    "method": method,
                    "path": path,
                    "protocol": protocol,
                    "status": int(payload["status"]),
                    "size": size,
                    "referer": payload.get("referer") or "-",
                    "agent": payload.get("agent") or "-",
                }
            )

    return entries


def analyze_requests(data):
    status_counts = Counter()
    method_counts = Counter()
    endpoint_counts = Counter()
    request_counts_by_ip = Counter()
    failed_logins = Counter()

    total_bytes = 0
    failed_requests = 0

    for row in data:
        ip = row["ip"]
        status = row["status"]
        method = row["method"]
        path = row["path"]

        request_counts_by_ip[ip] += 1
        status_counts[status] += 1
        method_counts[method] += 1
        endpoint_counts[path] += 1
        total_bytes += row["size"]

        if status >= 400:
            failed_requests += 1

        if status in {401, 403} and FAILED_LOGIN_PATH_PATTERN.search(path):
            failed_logins[ip] += 1

    total_requests = len(data)

    return {
        "total_requests": total_requests,
        "unique_ips": len(request_counts_by_ip),
        "failed_requests": failed_requests,
        "total_bytes": total_bytes,
        "avg_response_size": (total_bytes / total_requests) if total_requests else 0,
        "status_counts": dict(status_counts),
        "method_counts": dict(method_counts),
        "top_ips": request_counts_by_ip.most_common(5),
        "top_endpoints": endpoint_counts.most_common(5),
        "failed_logins": dict(failed_logins),
    }


def detect_suspicious_ips(failed_logins, threshold):
    suspicious = [
        (ip, count)
        for ip, count in failed_logins.items()
        if count >= threshold
    ]

    return sorted(suspicious, key=lambda item: (-item[1], item[0]))


def generate_report(results):
    lines = []
    lines.append("=== Secure Log Analysis Report ===")
    lines.append(f"Total requests: {results['total_requests']}")
    lines.append(f"Unique client IPs: {results['unique_ips']}")
    lines.append(f"Failed requests (4xx/5xx): {results['failed_requests']}")
    lines.append(f"Total bytes served: {results['total_bytes']}")
    lines.append(f"Average response size: {results['avg_response_size']:.2f} bytes")
    lines.append("")

    lines.append("Status code distribution:")
    for status, count in sorted(results["status_counts"].items()):
        lines.append(f"  {status}: {count}")
    lines.append("")

    lines.append("HTTP method distribution:")
    for method, count in sorted(results["method_counts"].items()):
        lines.append(f"  {method}: {count}")
    lines.append("")

    lines.append("Top 5 IPs by request volume:")
    if results["top_ips"]:
        for ip, count in results["top_ips"]:
            lines.append(f"  {ip}: {count}")
    else:
        lines.append("  No data")
    lines.append("")

    lines.append("Top 5 requested endpoints:")
    if results["top_endpoints"]:
        for endpoint, count in results["top_endpoints"]:
            lines.append(f"  {endpoint}: {count}")
    else:
        lines.append("  No data")
    lines.append("")

    lines.append("Suspicious IPs (failed login threshold met):")
    if results["suspicious_ips"]:
        for ip, count in results["suspicious_ips"]:
            lines.append(f"  {ip}: {count} failed login attempts")
    else:
        lines.append("  None detected")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Apache-style logs and detect suspicious IP activity."
    )
    parser.add_argument("log_file", help="Path to an Apache access log file")
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed login threshold to flag suspicious IPs (default: 5)",
    )
    args = parser.parse_args()

    data = parse_log(args.log_file)
    results = analyze_requests(data)
    results["suspicious_ips"] = detect_suspicious_ips(
        results["failed_logins"],
        args.threshold,
    )

    report = generate_report(results)
    print(report)

if __name__ == "__main__":
    main()
