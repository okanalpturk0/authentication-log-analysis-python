import re

file_name = "small_company_authentication_events.csv"
threshold = 5
night_hours = ["22", "23", "00", "01", "02", "03", "04", "05"]

def read_lines(file_name):
    with open(file_name, "r") as file:
        text = file.read()
    lines = text.split("\n")
    return lines[1:]

def find_ip(line):
    matches = re.findall(r"\d+\.\d+\.\d+\.\d+", line)
    return matches[0]

def find_time(line):
    matches = re.findall(r"\d\d:\d\d:\d\d", line)
    return matches[0]

def is_internal(ip):
    return ip[0:8] == "10.20.0."

lines = read_lines(file_name)

success_count = 0
night_failed = 0
external_failed = 0
failed_events = []
streak_pairs = []
streak_counts = []
alerts = []

for line in lines:
    if line == "":
        continue

    fields = line.split(",")
    date_time = fields[0]
    username = fields[1]
    status = fields[4]
    ip = find_ip(line)
    hour = find_time(line)[0:2]
    pair = username + "|" + ip

    if status == "success":
        success_count = success_count + 1

        if pair in streak_pairs:
            position = streak_pairs.index(pair)
            if streak_counts[position] >= threshold:
                alerts.append("CRITICAL | possible compromise | " + username
                              + " logged in from " + ip + " at " + date_time
                              + " after " + str(streak_counts[position])
                              + " failed attempts")
            streak_counts[position] = 0

    elif status == "failed":
        failed_events.append([date_time, username, ip])

        if pair in streak_pairs:
            position = streak_pairs.index(pair)
            streak_counts[position] = streak_counts[position] + 1
        else:
            streak_pairs.append(pair)
            streak_counts.append(1)

        if hour in night_hours:
            night_failed = night_failed + 1
        if not is_internal(ip):
            external_failed = external_failed + 1

pairs = []
for event in failed_events:
    pair = event[1] + "|" + event[2]
    if pair not in pairs:
        pairs.append(pair)

for pair in pairs:
    count = 0
    for event in failed_events:
        if event[1] + "|" + event[2] == pair:
            count = count + 1
    if count >= threshold:
        parts = pair.split("|")
        alerts.append("HIGH | brute force | " + parts[0] + " from " + parts[1]
                      + " | " + str(count) + " failed attempts")

failed_ips = []
for event in failed_events:
    if event[2] not in failed_ips:
        failed_ips.append(event[2])

for ip in failed_ips:
    users = []
    attempts = 0
    for event in failed_events:
        if event[2] == ip:
            attempts = attempts + 1
            if event[1] not in users:
                users.append(event[1])
    if len(users) >= threshold:
        alerts.append("HIGH | password spraying | " + ip + " | "
                      + str(attempts) + " failed attempts against "
                      + str(len(users)) + " different accounts")

total = success_count + len(failed_events)

report = "AUTHENTICATION LOG REPORT\n"
report = report + "=========================\n"
report = report + "Total events: " + str(total) + "\n"
report = report + "Successful logins: " + str(success_count) + "\n"
report = report + "Failed logins: " + str(len(failed_events)) + "\n"
report = report + "Failed from external IPs: " + str(external_failed) + "\n"
report = report + "Failed at night (22:00-05:59): " + str(night_failed) + "\n"
report = report + "\nALERTS (" + str(len(alerts)) + ")\n"
report = report + "\n".join(sorted(alerts)) + "\n"

print(report)

with open("report.txt", "w") as file:
    file.write(report)
