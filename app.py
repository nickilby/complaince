import streamlit as st
from prometheus_api_client import PrometheusConnect
import pandas as pd
import re
import json
from collections import defaultdict

# Configure Prometheus connection
PROMETHEUS_URL = "https://prometheus.zengenti.io/"
prom = PrometheusConnect(url=PROMETHEUS_URL, disable_ssl=True)

# Query for the VM power state
QUERY = 'vmware_vm_power_state == 1'

# Function to extract alias and role from VM name
def extract_alias_role(vm_name):
    match = re.match(r"z-([a-zA-Z0-9-]+)-([A-Za-z]+)\d*", vm_name)
    if match:
        alias = match.group(1)
        role = match.group(2)
        return alias, role
    return None, None

# Function to query Prometheus and return the results
def query_prometheus():
    results = prom.custom_query(query=QUERY)
    if results:
        df = pd.json_normalize(results)
        df['alias'], df['role'] = zip(*df['metric.vm_name'].apply(extract_alias_role))
        df = df.drop(columns=['metric.__name__', 'metric.instance', 'metric.dc_name', 'metric.environment', 'metric.job'], errors='ignore')
        if 'value' in df.columns:
            df['value'] = pd.to_numeric(df['value'], errors='coerce')
        return df
    else:
        st.warning("No results found from Prometheus.")
        return None

# Function to load rules from a JSON file
def load_rules(file_path):
    try:
        with open(file_path, 'r') as file:
            rules = json.load(file)
        return rules
    except Exception as e:
        st.error(f"Error loading rules file: {e}")
        return []

# Function to check for compliance violations
def check_compliance(vm_data, rules):
    vm_host_mapping = defaultdict(lambda: defaultdict(list))

    # Organize VM data by alias and role
    for _, row in vm_data.iterrows():
        alias, role = row['alias'], row['role']
        if alias and role:
            vm_host_mapping[alias][role].append(row['metric.host_name'])

    violations = []

    # Iterate through the rules and check for violations
    for alias, roles in vm_host_mapping.items():
        for role, hosts in roles.items():
            for rule in rules:
                # Check role-specific shared host rules
                if rule.get("role") == role and rule.get("alias_shared_host") is False:
                    if len(hosts) != len(set(hosts)):  # Duplicate hosts mean a violation
                        violations.append({"alias": alias, "violation": f"Role '{role}' VMs should not share the same host."})

                # Check multi-role rules (e.g., CMS + SQL)
                if "roles" in rule:
                    roles_in_rule = rule["roles"]
                    if all(r in roles for r in roles_in_rule):  # All roles exist
                        combined_hosts = set()
                        for r in roles_in_rule:
                            combined_hosts.update(roles[r])
                        if len(combined_hosts) > 1:  # Roles span multiple hosts
                            violations.append({"alias": alias, "violation": f"Roles {roles_in_rule} must be on the same host."})
    
    # Group and deduplicate violations by alias
    grouped_violations = defaultdict(set)
    for violation in violations:
        grouped_violations[violation["alias"]].add(violation["violation"])
    
    return grouped_violations

# Streamlit UI
st.title("VMware VM Compliance")

# Check if the data already exists in session state, otherwise load it
if 'df' not in st.session_state:
    st.session_state.df = query_prometheus()

# Add button to refresh Prometheus query data
if st.button("Refresh Data"):
    st.session_state.df = query_prometheus()

    if st.session_state.df is not None:
        st.write("Data refreshed successfully!")

        # Load rules from a JSON file
        rules = load_rules("rules.json")  # Adjust the file path to your actual rules file

        # Compliance Check
        grouped_violations = check_compliance(st.session_state.df, rules)

        # Store violations in session state
        st.session_state.violations = grouped_violations

        # Display the number of violations
        num_violations = sum(len(v) for v in grouped_violations.values())
        st.subheader(f"Number of Violations: {num_violations}")

        if grouped_violations:
            st.error("Compliance Violations Found!")

            # Display the violations grouped by alias
            for alias, violations in grouped_violations.items():
                st.write(f"Violations: {alias}")
                for violation in sorted(violations):
                    st.write(f"  - {violation}")
        else:
            st.success("All VMs are compliant!")
    else:
        st.warning("No data found from Prometheus.")

# Search bar to filter by alias or role
search_alias = st.text_input("Search by Alias", "")
search_role = st.text_input("Search by Role", "")
if search_alias:
    filtered_df = st.session_state.df[st.session_state.df['alias'].str.contains(search_alias, case=False, na=False)]
elif search_role:
    filtered_df = st.session_state.df[st.session_state.df['role'].str.contains(search_role, case=False, na=False)]
else:
    filtered_df = st.session_state.df

# Display the filtered data
st.subheader("VM Power State Data")
st.dataframe(filtered_df)

# Visualization of Violations
if 'violations' in st.session_state:
    violation_count_by_alias = pd.Series({alias: len(violations) for alias, violations in st.session_state.violations.items()})
    if not violation_count_by_alias.empty:
        st.bar_chart(violation_count_by_alias)
