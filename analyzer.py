# import pandas as pd
# df = pd.read_csv("data/siem_alerts.csv")
# print(df)


# alert_counts = df["alert_name"].value_counts()

# print("Total Alerts by Type:")
# print(alert_counts)

# false_positive_counts = df[df["status"] == "False Positive"]["alert_name"].value_counts()


# print("\nFalse Positive Alerts by Type:")
# print(false_positive_counts)

import pandas as pd


df = pd.read_csv("data/siem_alerts.csv")


total_alerts = df.groupby("alert_name").size()


false_positives = (
    df[df["status"] == "False Positive"]
    .groupby("alert_name")
    .size()
)

false_positive_rate = (false_positives / total_alerts) * 100

print("False Positive Rate:")
print(false_positive_rate)


# High false positive threshold
threshold = 50

# High false positive alerts identify karna
high_fp_alerts = false_positive_rate[
    false_positive_rate >= threshold
]

print("\nHigh False Positive Alerts:")
print(high_fp_alerts)



# Tuning Recommendations

def get_recommendation(alert_name, fp_rate):

    if fp_rate >= 80:
        return "High priority tuning: review detection conditions and add trusted-source exclusions."

    elif fp_rate >= 50:
        return "Tune detection threshold, review trusted sources, and add additional conditions."

    elif fp_rate >= 25:
        return "Monitor the alert and consider adding additional filtering conditions."

    else:
        return "No immediate tuning required."


print("\nTuning Recommendations:")

for alert_name, fp_rate in false_positive_rate.items():
    recommendation = get_recommendation(alert_name, fp_rate)

    print(f"\nAlert: {alert_name}")
    print(f"False Positive Rate: {fp_rate:.2f}%")
    print(f"Recommendation: {recommendation}")