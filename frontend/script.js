
const API_URL = "http://127.0.0.1:8000/alerts";

let severityChart = null;
let threatChart = null;
let allAlerts = [];

// Update dashboard charts
function updateCharts(alerts) {

    const severityCounts = {
        High: 0,
        Medium: 0,
        Low: 0
    };

    const threatCounts = {};

    alerts.forEach(alert => {
        if (severityCounts[alert.severity] !== undefined) {
            severityCounts[alert.severity]++;
        }

        threatCounts[alert.alert_type] =
            (threatCounts[alert.alert_type] || 0) + 1;
    });

    const severityData = {
        labels: ["High", "Medium", "Low"],
        datasets: [{
            data: [
                severityCounts.High,
                severityCounts.Medium,
                severityCounts.Low
            ],
            backgroundColor: [
                "#f87171",
                "#fbbf24",
                "#4ade80"
            ],
            borderWidth: 0
        }]
    };

    if (severityChart) {
        severityChart.data = severityData;
        severityChart.update();
    } else {
        severityChart = new Chart(
            document.getElementById("severityChart"),
            {
                type: "doughnut",
                data: severityData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: "bottom",
                            labels: {
                                color: "#e2e8f0"
                            }
                        }
                    }
                }
            }
        );
    }

    const threatData = {
        labels: Object.keys(threatCounts),
        datasets: [{
            label: "Number of Alerts",
            data: Object.values(threatCounts),
            backgroundColor: "#38bdf8",
            borderRadius: 6
        }]
    };

    if (threatChart) {
        threatChart.data = threatData;
        threatChart.update();
    } else {
        threatChart = new Chart(
            document.getElementById("threatChart"),
            {
                type: "bar",
                data: threatData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            ticks: { color: "#e2e8f0" },
                            grid: { display: false }
                        },
                        y: {
                            beginAtZero: true,
                            ticks: {
                                color: "#e2e8f0",
                                precision: 0
                            },
                            grid: { color: "#334155" }
                        }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            }
        );
    }
}

// Display filtered alerts
function displayAlerts(alerts) {

    const table = document.getElementById("alerts-table");

    table.innerHTML = "";

    if (alerts.length === 0) {
        table.innerHTML = `
            <tr>
                <td colspan="6">No matching alerts found.</td>
            </tr>
        `;
        return;
    }

    alerts.forEach(alert => {

        const row = document.createElement("tr");

        const values = [
            alert.id,
            alert.alert_type,
            alert.source_ip,
            alert.severity,
            alert.description,
            alert.created_at
        ];

        values.forEach((value, index) => {

            const cell = document.createElement("td");

            if (index === 3) {
                const badge = document.createElement("span");

                badge.className = `severity ${alert.severity}`;
                badge.textContent = alert.severity;

                cell.appendChild(badge);
            } else {
                cell.textContent = value ?? "";
            }

            row.appendChild(cell);
        });

        table.appendChild(row);
    });
}

// Apply search and filters
function applyFilters() {

    const searchIP =
        document.getElementById("search-ip").value
        .trim()
        .toLowerCase();

    const severity =
        document.getElementById("severity-filter").value;

    const threatType =
        document.getElementById("type-filter").value;

    const filteredAlerts = allAlerts.filter(alert => {

        const matchesIP =
            alert.source_ip.toLowerCase().includes(searchIP);

        const matchesSeverity =
            severity === "" || alert.severity === severity;

        const matchesType =
            threatType === "" || alert.alert_type === threatType;

        return matchesIP && matchesSeverity && matchesType;
    });

    displayAlerts(filteredAlerts);
}

// Fetch alerts from FastAPI
async function loadAlerts() {

    const errorMessage =
        document.getElementById("error-message");

    try {

        const response = await fetch(API_URL);

        if (!response.ok) {
            throw new Error("Unable to fetch alerts");
        }

        allAlerts = await response.json();

        errorMessage.textContent = "";

        // Update summary cards using all alerts
        document.getElementById("total-alerts").textContent =
            allAlerts.length;

        document.getElementById("high-alerts").textContent =
            allAlerts.filter(a => a.severity === "High").length;

        document.getElementById("medium-alerts").textContent =
            allAlerts.filter(a => a.severity === "Medium").length;

        document.getElementById("low-alerts").textContent =
            allAlerts.filter(a => a.severity === "Low").length;

        // Update charts using all alerts
        updateCharts(allAlerts);

        // Display alerts according to current filters
        applyFilters();

    } catch (error) {

        console.error("Dashboard error:", error);

        errorMessage.textContent =
            "Unable to connect to NetShield API. Check whether FastAPI is running.";

        document.getElementById("alerts-table").innerHTML = `
            <tr>
                <td colspan="6">Could not load alerts.</td>
            </tr>
        `;
    }
}

// Listen for search and filter changes
document.getElementById("search-ip")
    .addEventListener("input", applyFilters);

document.getElementById("severity-filter")
    .addEventListener("change", applyFilters);

document.getElementById("type-filter")
    .addEventListener("change", applyFilters);

// Load alerts initially
loadAlerts();

// Refresh every 10 seconds
setInterval(loadAlerts, 10000);
