import streamlit as st
from prometheus_api_client import PrometheusConnect
import pandas as pd
import re
import json
from collections import defaultdict

# Configure Prometheus connection
PROMETHEUS_URL = "https://prometheus.zengenti.io/"
prom = PrometheusConnect(url=PROMETHEUS_URL, disable_ssl=True)

# Query for the VM power state as this returns all the facts we need
QUERY = 'vmware_vm_power_state == 1'

# Function to extract alias and role from VM name
def extract_alias_role(vm_name):
    match = re.match(r"z-(\d+-\d+)-([A-Za-z]+)\d*", vm_name)
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
        df = df.drop(columns=['metric.__name__', 'metric.instance', 'metric.dc_name', 'metric.environment'], errors='ignore')
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

# Function to check for compliance violations (generic rule application)
def check_compliance(vm_data, rules):
    vm_host_mapping = defaultdict(lambda: defaultdict(list))
    for _, row in vm_data.iterrows():
        alias, role = row['alias'], row['role']
        if alias and role:
            vm_host_mapping[alias][role].append(row['metric.host_name'])

    violations = []

    # Iterate through the rules and check for violations
    for alias, roles in vm_host_mapping.items():
        for rule in rules:
            # Check if the rule applies to multiple roles (like CMS and SQL sharing the same host)
            if "roles" in rule:
                roles_in_rule = rule["roles"]
                if all(role in roles for role in roles_in_rule):  # All roles must exist for this check
                    # Check that all the VMs for these roles are on the same host
                    hosts = set()
                    for role in roles_in_rule:
                        hosts.update(roles.get(role, []))
                    if len(hosts) != 1:
                        violation = f"Violation: VMs of roles {roles_in_rule} in alias '{alias}' should be on the same ESXi host."
                        violations.append(violation)

            # Check other individual roles for the shared host rule
            for role, hosts in roles.items():
                for rule in rules:
                    if rule.get("role") == role and rule.get("alias_shared_host") is False:
                        if len(hosts) != len(set(hosts)):
                            violation = f"Violation: VMs of '{alias}' and role '{role}' should not be on the same ESXi host."
                            violations.append(violation)

    return violations

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
        violations = check_compliance(st.session_state.df, rules)
        
        # Display the number of violations
        num_violations = len(violations)
        st.subheader(f"Number of Violations: {num_violations}")
        
        if violations:
            st.error("Compliance Violations Found!")
            st.write(violations)
        else:
            st.success("All VMs are compliant!")
    else:
        st.warning("No data found from Prometheus.")

# Search bar to filter by alias (separate from the refresh button logic)
search_alias = st.text_input("Search by Alias", "")
if search_alias:
    filtered_df = st.session_state.df[st.session_state.df['alias'].str.contains(search_alias, case=False, na=False)]
else:
    filtered_df = st.session_state.df

# Display the filtered data as a table, including the alias and role columns for human readability
st.subheader("VM Power State Data")
st.dataframe(filtered_df)
