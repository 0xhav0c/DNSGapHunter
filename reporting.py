import csv
import os
import datetime
from typing import List, Dict, Tuple, Any

def generate_html_report(results, no_dns_records, security_bypassed_count, security_blocked_count, security_block_counts, test_type, timestamp):
    """
    Generates HTML report for analysis results.
    """
    # Format timestamp for display (from YYYY-MM-DD-HH-MM to DD/MM/YYYY HH:MM)
    try:
        # Parse timestamp from 2025-05-06-13-40 format
        dt = datetime.datetime.strptime(timestamp, "%Y-%m-%d-%H-%M")
        # Format as DD/MM/YYYY HH:MM
        formatted_date = dt.strftime("%d/%m/%Y %H:%M")
    except:
        # If formatting fails, use original timestamp
        formatted_date = timestamp
    
    # Calculate source statistics and count terminated domains
    source_stats = {}
    terminated_domains_count = 0
    for domain, status, security_status, _, sources in results + no_dns_records:
        for source in sources:
            if source not in source_stats:
                source_stats[source] = {
                    'total': 0,
                    'bypassed': 0,
                    'blocked': 0,
                    'no_dns': 0,
                    'terminated': 0
                }
            source_stats[source]['total'] += 1
            
            if status == 'valid':
                if security_status == 'Post-Attack Terminated Domain':
                    source_stats[source]['terminated'] += 1
                    terminated_domains_count += 1
                elif security_status == 'DNSFW Bypassed' or security_status == 'Sinkhole Bypassed':
                    source_stats[source]['bypassed'] += 1
                elif security_status == 'DNSFW Blocked' or security_status == 'Sinkhole Address Blocked':
                    source_stats[source]['blocked'] += 1
            else:
                source_stats[source]['no_dns'] += 1

    results_dir = "test-results/sinkhole-dns-security" if test_type == "sinkhole" else "test-results/dns-fw"
    report_dir = f"{results_dir}/reports"
    os.makedirs(report_dir, exist_ok=True)
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>DNS SECURITY ANALYSIS TOOL - Analysis Report - {timestamp}</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
        <style>
            :root {{
                --primary-color: #3498db;
                --success-color: #2ecc71;
                --danger-color: #e74c3c;
                --warning-color: #f39c12;
                --dark-color: #2c3e50;
                --light-color: #ecf0f1;
            }}
            
            [data-theme="dark"] {{
                --bg-color: #1a1a1a;
                --text-color: #ffffff;
                --card-bg: #2d2d2d;
                --border-color: #404040;
                --hover-color: #3d3d3d;
                --shadow-color: rgba(0, 0, 0, 0.3);
            }}
            
            [data-theme="light"] {{
                --bg-color: #f5f6fa;
                --text-color: #2c3e50;
                --card-bg: #ffffff;
                --border-color: #e0e0e0;
                --hover-color: #f8f9fa;
                --shadow-color: rgba(0, 0, 0, 0.1);
            }}
            
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: 'Roboto', sans-serif;
                line-height: 1.6;
                color: var(--text-color);
                background-color: var(--bg-color);
                transition: background-color 0.3s ease, color 0.3s ease;
            }}
            
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 2rem;
            }}
            
            .header {{
                text-align: center;
                margin-bottom: 3rem;
                padding: 2rem;
                background: var(--card-bg);
                border-radius: 10px;
                box-shadow: 0 2px 10px var(--shadow-color);
            }}
            
            .header h1 {{
                color: var(--primary-color);
                margin-bottom: 1rem;
                font-size: 2.5rem;
            }}
            
            .header p {{
                color: var(--text-color);
                opacity: 0.8;
                font-size: 1.1rem;
            }}
            
            .section {{
                background: var(--card-bg);
                padding: 2rem;
                margin-bottom: 2rem;
                border-radius: 10px;
                box-shadow: 0 2px 10px var(--shadow-color);
            }}
            
            .section h2 {{
                color: var(--text-color);
                margin-bottom: 1.5rem;
                padding-bottom: 0.5rem;
                border-bottom: 2px solid var(--border-color);
            }}
            
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 1.5rem;
                margin: 2rem 0;
            }}
            
            .stat-box {{
                background: var(--card-bg);
                padding: 1.5rem;
                border-radius: 10px;
                text-align: center;
                box-shadow: 0 2px 10px var(--shadow-color);
                transition: transform 0.3s ease;
                border: 1px solid var(--border-color);
            }}
            
            .stat-box:hover {{
                transform: translateY(-5px);
            }}
            
            .stat-box h3 {{
                color: var(--text-color);
                margin-bottom: 0.5rem;
                font-size: 1.1rem;
            }}
            
            .stat-box p {{
                font-size: 2rem;
                font-weight: bold;
                color: var(--primary-color);
            }}
            
            .chart-container {{
                position: relative;
                height: 300px;
                margin: 1rem 0;
                background: var(--card-bg);
                padding: 1rem;
                border-radius: 10px;
                border: 1px solid var(--border-color);
            }}
            
            .chart-grid {{
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 2rem;
                margin: 2rem 0;
            }}
            
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 2rem 0;
                background: var(--card-bg);
                border-radius: 10px;
                overflow: hidden;
                box-shadow: 0 2px 10px var(--shadow-color);
            }}
            
            th, td {{
                padding: 1rem;
                text-align: left;
                border-bottom: 1px solid var(--border-color);
                color: var(--text-color);
            }}
            
            th {{
                background: var(--card-bg);
                font-weight: 500;
            }}
            
            tr:hover {{
                background: var(--hover-color);
            }}
            
            .badge {{
                display: inline-block;
                padding: 0.25rem 0.5rem;
                border-radius: 20px;
                font-size: 0.8rem;
                font-weight: 500;
            }}
            
            .badge-success {{
                background: var(--success-color);
                color: white;
            }}
            
            .badge-danger {{
                background: var(--danger-color);
                color: white;
            }}
            
            .badge-warning {{
                background: var(--warning-color);
                color: white;
            }}
            
            .theme-switch {{
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 1000;
            }}
            
            .theme-switch button {{
                background: var(--card-bg);
                border: 1px solid var(--border-color);
                color: var(--text-color);
                padding: 0.5rem 1rem;
                border-radius: 20px;
                cursor: pointer;
                transition: all 0.3s ease;
            }}
            
            .theme-switch button:hover {{
                background: var(--hover-color);
            }}
            
            @media (max-width: 768px) {{
                .chart-grid {{
                    grid-template-columns: 1fr;
                }}
                
                .stats {{
                    grid-template-columns: 1fr;
                }}
                
                .container {{
                    padding: 1rem;
                }}
                
                .section {{
                    padding: 1rem;
                }}
                
                .theme-switch {{
                    top: 10px;
                    right: 10px;
                }}
            }}
        </style>
    </head>
    <body data-theme="dark">
        <div class="theme-switch">
            <button onclick="toggleTheme()">DARK</button>
        </div>
        
        <div class="container">
            <div class="header">
                <h1>DNS SECURITY ANALYSIS TOOL - Analysis Report</h1>
                <p>Assessment Type: {'Sinkhole DNS Security' if test_type == 'sinkhole' else 'DNS Firewall'}</p>
                <p>Date: {formatted_date}</p>
            </div>
            
            <div class="section">
                <h2>General Statistics</h2>
                <div class="stats">
                    <div class="stat-box">
                        <h3>Total Domains</h3>
                        <p>{len(results) + len(no_dns_records)}</p>
                    </div>
                    <div class="stat-box">
                        <h3>Valid for Analysis</h3>
                        <p>{len(results)}</p>
                    </div>
                    <div class="stat-box">
                        <h3>No DNS Record</h3>
                        <p>{len(no_dns_records)}</p>
                    </div>
                    <div class="stat-box">
                        <h3>Terminated Domains</h3>
                        <p>{terminated_domains_count}</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Domain and Security Status</h2>
                <div class="chart-grid">
                    <div class="chart-container">
                        <canvas id="domainChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <canvas id="securityChart"></canvas>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Source Distribution</h2>
                <div class="chart-container">
                    <canvas id="sourceChart"></canvas>
                </div>
                <table>
                    <tr>
                        <th>Source</th>
                        <th>Total Domains</th>
                        <th>Bypassed</th>
                        <th>Blocked</th>
                        <th>Terminated</th>
                        <th>No DNS Record</th>
                    </tr>
    """
    
    for source, stats in sorted(source_stats.items(), key=lambda x: x[1]['total'], reverse=True):
        html_content += f"""
                    <tr>
                        <td>{source}</td>
                        <td><span class="badge badge-warning">{stats['total']}</span></td>
                        <td><span class="badge badge-success">{stats['bypassed']}</span></td>
                        <td><span class="badge badge-danger">{stats['blocked']}</span></td>
                        <td><span class="badge badge-warning">{stats['terminated']}</span></td>
                        <td><span class="badge badge-warning">{stats['no_dns']}</span></td>
                    </tr>
        """
    
    html_content += """
                </table>
            </div>
            
            <div class="section">
                <h2>Blocking Statistics</h2>
                <table>
                    <tr>
                        <th>IP Address</th>
                        <th>Blocked Count</th>
                    </tr>
    """
    
    for ip, count in sorted(security_block_counts.items(), key=lambda x: x[1], reverse=True):
        if count > 0:
            html_content += f"""
                    <tr>
                        <td>{ip}</td>
                        <td><span class="badge badge-danger">{count}</span></td>
                    </tr>
            """
    
    html_content += """
                </table>
            </div>
        </div>
        
        <script>
            window.addEventListener('load', function() {
                const domainCtx = document.getElementById('domainChart').getContext('2d');
                window.domainChart = new Chart(domainCtx, {
                    type: 'pie',
                    data: {
                        labels: ['Valid for Analysis', 'No DNS Record', 'Terminated Domains'],
                        datasets: [{
                            data: ["""
    html_content += f"{len(results)}, {len(no_dns_records)}, {terminated_domains_count}"
    html_content += """],
                            backgroundColor: ['#2ecc71', '#e74c3c', '#f39c12'],
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'right',
                                labels: {
                                    color: '#ffffff'
                                }
                            },
                            tooltip: {
                                callbacks: {
                                    label: function(context) {
                                        const label = context.label || '';
                                        const value = context.raw || 0;
                                        const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                        const percentage = Math.round((value / total) * 100);
                                        return `${label}: ${value} (${percentage}%)`;
                                    }
                                }
                            }
                        }
                    }
                });
                
                const securityCtx = document.getElementById('securityChart').getContext('2d');
                window.securityChart = new Chart(securityCtx, {
                    type: 'bar',
                    data: {
                        labels: ["""
    if test_type == "sinkhole":
        html_content += "'Sinkhole Bypassed', 'Sinkhole Blocked'"
    else:  # dnsfw
        html_content += "'DNSFW Bypassed', 'DNSFW Blocked'"

    html_content += """],
                        datasets: [{
                            label: 'Domain Count',
                            data: ["""
    html_content += f"{security_bypassed_count}, {security_blocked_count}"
    html_content += """],
                            backgroundColor: ['#3498db', '#e74c3c'],
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: {
                                    stepSize: 1,
                                    color: '#ffffff'
                                },
                                grid: {
                                    color: '#404040'
                                }
                            },
                            x: {
                                ticks: {
                                    color: '#ffffff'
                                }
                            }
                        },
                        plugins: {
                            legend: {
                                display: false
                            }
                        }
                    }
                });
                
                const sourceCtx = document.getElementById('sourceChart').getContext('2d');
                window.sourceChart = new Chart(sourceCtx, {
                    type: 'pie',
                    data: {
                        labels: ["""
    html_content += ", ".join([f"'{source}'" for source in source_stats.keys()])
    html_content += """],
                        datasets: [{
                            data: ["""
    html_content += ", ".join([str(stats['total']) for stats in source_stats.values()])
    html_content += """],
                            backgroundColor: [
                                '#3498db',
                                '#e74c3c',
                                '#2ecc71',
                                '#f39c12',
                                '#9b59b6',
                                '#1abc9c'
                            ],
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'right',
                                labels: {
                                    color: '#ffffff'
                                }
                            },
                            tooltip: {
                                callbacks: {
                                    label: function(context) {
                                        const label = context.label || '';
                                        const value = context.raw || 0;
                                        const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                        const percentage = Math.round((value / total) * 100);
                                        const source = label;
                                        const stats = {"""
    
    stats_js = []
    for source, stats in source_stats.items():
        stats_js.append(f"'{source}': {{total: {stats['total']}, bypassed: {stats['bypassed']}, blocked: {stats['blocked']}, no_dns: {stats['no_dns']}, terminated: {stats['terminated']}}}")
    
    html_content += ", ".join(stats_js)
    
    html_content += """
                                        };
                                        const sourceStats = stats[source];
                                        return [
                                            `${label}: ${value} (${percentage}%)`,
                                            `Bypassed: ${sourceStats.bypassed}`,
                                            `Blocked: ${sourceStats.blocked}`,
                                            `No DNS Record: ${sourceStats.no_dns}`,
                                            `Terminated: ${sourceStats.terminated}`
                                        ];
                                    }
                                }
                            }
                        }
                    }
                });
            });
            
            function toggleTheme() {
                const body = document.body;
                const currentTheme = body.getAttribute('data-theme');
                const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
                body.setAttribute('data-theme', newTheme);
                
                const button = document.querySelector('.theme-switch button');
                button.textContent = newTheme === 'dark' ? 'DARK' : 'LIGHT';
                
                const textColor = newTheme === 'dark' ? '#ffffff' : '#2c3e50';
                const gridColor = newTheme === 'dark' ? '#404040' : '#e0e0e0';
                
                if (window.domainChart) {
                    window.domainChart.options.plugins.legend.labels.color = textColor;
                    window.domainChart.update();
                }
                
                if (window.securityChart) {
                    window.securityChart.options.scales.y.grid.color = gridColor;
                    window.securityChart.options.scales.y.ticks.color = textColor;
                    window.securityChart.options.scales.x.ticks.color = textColor;
                    window.securityChart.update();
                }
                
                if (window.sourceChart) {
                    window.sourceChart.options.plugins.legend.labels.color = textColor;
                    window.sourceChart.update();
                }
            }
        </script>
    </body>
    </html>
    """
    
    with open(f'{report_dir}/report_{timestamp}.html', 'w', encoding='utf-8') as f:
        f.write(html_content)
        
    return f'{report_dir}/report_{timestamp}.html' 