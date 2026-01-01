#!/bin/bash

# This script will read the checks.txt file and process it.

# Associative arrays to store check results and details
declare -A check_results
declare -A check_details

# --- CHECK FUNCTIONS ---

# Function to check password minimum length
check_password_length() {
    local pam_file="/etc/pam.d/common-password"
    local min_len_req=8

    if [ ! -f "$pam_file" ]; then
        check_results["password"]="NOT_FOUND"
        check_details["password"]="Password policy file not found: $pam_file"
        return
    fi

    local minlen_line=$(grep -E 'minlen=[0-9]+' "$pam_file")
    if [ -z "$minlen_line" ]; then
        check_results["password"]="FAIL"
        check_details["password"]="No 'minlen' setting found in $pam_file."
        return
    fi

    local minlen_val=$(echo "$minlen_line" | grep -oE 'minlen=[0-9]+' | cut -d'=' -f2)
    if [ "$minlen_val" -gt "$min_len_req" ]; then
        check_results["password"]="OK"
        check_details["password"]="Minimum password length is $minlen_val (required > $min_len_req)."
    else
        check_results["password"]="FAIL"
        check_details["password"]="Minimum password length is $minlen_val (required > $min_len_req)."
    fi
}

# Function to check for an active firewall
check_firewall() {
    if command -v ufw &> /dev/null && systemctl is-active --quiet ufw; then
        check_results["firewall"]="OK"
        check_details["firewall"]="UFW service is active."
        return
    fi

    if command -v iptables &> /dev/null; then
        if systemctl is-active --quiet iptables; then
            check_results["firewall"]="OK"
            check_details["firewall"]="iptables service is active."
            return
        fi
        if [ "$EUID" -eq 0 ]; then
            if [ $(iptables -L -n 2>/dev/null | wc -l) -gt 5 ]; then
                check_results["firewall"]="OK"
                check_details["firewall"]="iptables appears to have rules configured."
                return
            fi
        else
            check_results["firewall"]="WARN"
            check_details["firewall"]="Cannot check iptables rules without root privileges."
            return
        fi
    fi

    check_results["firewall"]="FAIL"
    check_details["firewall"]="No active firewall (UFW or iptables) detected."
}

# Function to check for remote root login
check_root_login() {
    local sshd_config="/etc/ssh/ssh_config"
    if [ ! -f "$sshd_config" ]; then
        check_results["root_access"]="NOT_FOUND"
        check_details["root_access"]="SSH config file not found: $sshd_config"
        return
    fi

    if grep -q -E '^\s*PermitRootLogin\s+yes' "$sshd_config"; then
        check_results["root_access"]="FAIL"
        check_details["root_access"]="SSH PermitRootLogin is set to 'yes'."
    else
        check_results["root_access"]="OK"
        check_details["root_access"]="SSH PermitRootLogin is not set to 'yes'."
    fi
}

# Function to check for automatic updates
check_automatic_updates() {
    if [ "$EUID" -ne 0 ]; then
        check_results["updates"]="WARN"
        check_details["updates"]="This check requires root privileges. Please run with sudo."
        return
    fi

    local unattended_active=$(systemctl is-active --quiet unattended-upgrades && echo "true" || echo "false")
    local timer_active=$(systemctl is-active --quiet apt-daily-upgrade.timer && echo "true" || echo "false")
    local config_ok=false
    local config_file="/etc/apt/apt.conf.d/20auto-upgrades"

    if [ -f "$config_file" ] && grep -q -E '^\s*APT::Periodic::Unattended-Upgrade\s+"1";' "$config_file"; then
        config_ok=true
    fi

    if $unattended_active && $timer_active && $config_ok; then
        check_results["updates"]="OK"
        check_details["updates"]="System is configured for automatic updates."
    else
        check_results["updates"]="FAIL"
        check_details["updates"]="System is not fully configured for automatic updates."
    fi
}

# Function to check for password lockout policy
check_block_policy() {
    local pam_file="/etc/pam.d/common-password"
    local max_retries=5

    if [ ! -f "$pam_file" ]; then
        check_results["block_policy"]="NOT_FOUND"
        check_details["block_policy"]="Password policy file not found: $pam_file"
        return
    fi

    local retry_line=$(grep -E 'retry=[0-9]+' "$pam_file")
    if [ -z "$retry_line" ]; then
        check_results["block_policy"]="FAIL"
        check_details["block_policy"]="No 'retry' setting found. Account lockout is not configured."
        return
    fi

    local retry_val=$(echo "$retry_line" | grep -oE 'retry=[0-9]+' | cut -d'=' -f2)
    if [ "$retry_val" -le "$max_retries" ]; then
        check_results["block_policy"]="OK"
        check_details["block_policy"]="Account lockout retry count is $retry_val (limit: $max_retries)."
    else
        check_results["block_policy"]="FAIL"
        check_details["block_policy"]="Account lockout retry count is $retry_val (limit: $max_retries)."
    fi
}

# --- REPORTING FUNCTION ---

generate_report() {
    # Define colors
    local COLOR_GREEN='\033[0;32m'
    local COLOR_RED='\033[0;31m'
    local COLOR_YELLOW='\033[0;33m'
    local COLOR_BLUE='\033[0;34m'
    local COLOR_NC='\033[0m' # No Color

    printf "\n"
    printf "${COLOR_BLUE}======================================================================${COLOR_NC}\n"
    printf "${COLOR_BLUE}|                    CIS Security Scan Report                        |${COLOR_NC}\n"
    printf "${COLOR_BLUE}======================================================================${COLOR_NC}\n"
    printf "| %-20s | %-11s | %-30s |\n" "Check" "Status" "Details"
    printf "|------------------------|-------------|--------------------------------|\n"

    # Define the order of checks for the report
    local checks_order=("password" "firewall" "root_access" "updates" "block_policy")

    for check_name in "${checks_order[@]}"; do
        local status=${check_results[$check_name]:-"NOT_RUN"}
        local details=${check_details[$check_name]:-"Check was not triggered."}
        local status_color

        case $status in
            "OK") status_color=$COLOR_GREEN ;;
            "FAIL") status_color=$COLOR_RED ;;
            "WARN") status_color=$COLOR_YELLOW ;;
            *) status_color=$COLOR_NC ;;
        esac

        printf "| %-20s | ${status_color}%-11s${COLOR_NC} | %-30s |\n" "$check_name" "$status" "$details"
    done

    printf "${COLOR_BLUE}======================================================================${COLOR_NC}\n"
    printf "\n"
}


# --- MAIN EXECUTION ---

# Check if the checks.txt file exists
if [ ! -f "checks.txt" ]; then
    echo "Error: checks.txt file not found."
    exit 1
fi

echo "Starting security checks..."

# Read the file line by line
while IFS= read -r line; do
    line=${line%$'\r'}
    check_name=$(echo "$line" | cut -d' ' -f1)
    check_value=$(echo "$line" | cut -d' ' -f2)

    case $check_name in
        "password")
            [ "$check_value" -eq 1 ] && check_password_length
            ;;
        "firewall")
            [ "$check_value" -eq 1 ] && check_firewall
            ;;
        "root_access")
            [ "$check_value" -eq 1 ] && check_root_login
            ;;
        "updates")
            [ "$check_value" -eq 1 ] && check_automatic_updates
            ;;
        "block_policy")
            [ "$check_value" -eq 1 ] && check_block_policy
            ;;
    esac
done < "checks.txt"

# Generate the final report
generate_report

echo "Finished processing checks.txt"
