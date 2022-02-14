#!/bin/zsh

##  This script will attempt to audit all of the settings based on the installed profile.

##  This script is provided as-is and should be fully tested on a system that is not in a production environment.  

###################  Variables  ###################

pwpolicy_file=""

###################  COMMANDS START BELOW THIS LINE  ###################

## Must be run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# path to PlistBuddy
plb="/usr/libexec/PlistBuddy"

# get the currently logged in user
CURRENT_USER=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ { print $3 }')
CURR_USER_UID=$(/usr/bin/id -u $CURR_USER)

# get system architecture
arch=$(/usr/bin/arch)

# configure colors for text
RED='\e[31m'
STD='\e[39m'
GREEN='\e[32m'
YELLOW='\e[33m'

# setup files
audit_plist_managed="/Library/Managed Preferences/org.800-53r5_moderate.audit.plist"

if [[ ! -e "$audit_plist_managed" ]];then
    audit_plist_managed="/Library/Preferences/org.800-53r5_moderate.audit.plist"
fi

audit_plist="/Library/Preferences/org.800-53r5_moderate.audit.plist"
audit_log="/Library/Logs/800-53r5_moderate_baseline.log"

lastComplianceScan=$(defaults read /Library/Preferences/org.800-53r5_moderate.audit.plist lastComplianceCheck)

if [[ $lastComplianceScan == "" ]];then
    lastComplianceScan="No scans have been run"
fi


ask() {
    # Default to return 0 instead of checking for flags
    return 0
}


# Generate the Compliant and Non-Compliant counts. Returns: Array (Compliant, Non-Compliant)
compliance_count(){
    compliant=0
    non_compliant=0

    results=$(/usr/libexec/PlistBuddy -c "Print" /Library/Preferences/org.800-53r5_moderate.audit.plist)
    
    while IFS= read -r line; do
        if [[ "$line" =~ "finding = false" ]]; then
            compliant=$((compliant+1))
        fi
        if [[ "$line" =~ "finding = true" ]]; then
            non_compliant=$((non_compliant+1))
        fi
    done <<< "$results"
    
    # Enable output of just the compliant or non-compliant numbers. 
    if [[ $1 = "compliant" ]]
    then
        echo $compliant
    elif [[ $1 = "non-compliant" ]]
    then
        echo $non_compliant
    else # no matching args output the array
        array=($compliant $non_compliant)
        echo ${array[@]}
    fi
}


generate_report(){
    count=($(compliance_count))
    compliant=${count[1]}
    non_compliant=${count[2]}
    
    total=$((non_compliant + compliant))
    percentage=$(printf %.2f $(( compliant * 100. / total )) )
    echo
    echo "Number of tests passed: ${GREEN}$compliant${STD}"
    echo "Number of test FAILED: ${RED}$non_compliant${STD}"
    echo "You are ${YELLOW}$percentage%${STD} percent compliant!"
}

view_report(){
    
    if [[ $lastComplianceScan == "No scans have been run" ]];then
        echo "no report to run, please run new scan"
    else
        generate_report
    fi
}

# Designed for use with MDM - single unformatted output of the Compliance Report
generate_stats(){
    count=($(compliance_count))
    compliant=${count[1]}
    non_compliant=${count[2]}
    
    total=$((non_compliant + compliant))
    percentage=$(printf %.2f $(( compliant * 100. / total )) )
    echo "PASSED: $compliant FAILED: $non_compliant, $percentage percent compliant!"
}

run_scan(){
# append to existing logfile
if [[ $(/usr/bin/tail -n 1 "$audit_log" 2>/dev/null) = *"Remediation complete" ]]; then
 	echo "$(date -u) Beginning 800-53r5_moderate baseline scan" >> "$audit_log"
else
 	echo "$(date -u) Beginning 800-53r5_moderate baseline scan" > "$audit_log"
fi

#echo "$(date -u) Beginning 800-53r5_moderate baseline scan" >> "$audit_log"

# run mcxrefresh
/usr/bin/mcxrefresh -u $CURR_USER_UID

# write timestamp of last compliance check
defaults write "$audit_plist" lastComplianceCheck "$(date)"
    
#####----- Rule: auth_pam_login_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2(1), IA-2(2), IA-2(8)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: auth_pam_login_smartcard_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_deny.so)' /etc/pam.d/login)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print auth_pam_login_smartcard_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print auth_pam_login_smartcard_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) auth_pam_login_smartcard_enforce passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" auth_pam_login_smartcard_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) auth_pam_login_smartcard_enforce failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" auth_pam_login_smartcard_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) auth_pam_login_smartcard_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" auth_pam_login_smartcard_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) auth_pam_login_smartcard_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" auth_pam_login_smartcard_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: auth_pam_su_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2(1), IA-2(2), IA-2(8)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: auth_pam_su_smartcard_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_rootok.so)' /etc/pam.d/su)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print auth_pam_su_smartcard_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print auth_pam_su_smartcard_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) auth_pam_su_smartcard_enforce passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" auth_pam_su_smartcard_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) auth_pam_su_smartcard_enforce failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" auth_pam_su_smartcard_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) auth_pam_su_smartcard_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" auth_pam_su_smartcard_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) auth_pam_su_smartcard_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" auth_pam_su_smartcard_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: auth_pam_sudo_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2(1), IA-2(2), IA-2(8)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: auth_pam_sudo_smartcard_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_deny.so)' /etc/pam.d/sudo)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print auth_pam_sudo_smartcard_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print auth_pam_sudo_smartcard_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) auth_pam_sudo_smartcard_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" auth_pam_sudo_smartcard_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) auth_pam_sudo_smartcard_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" auth_pam_sudo_smartcard_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) auth_pam_sudo_smartcard_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" auth_pam_sudo_smartcard_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) auth_pam_sudo_smartcard_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" auth_pam_sudo_smartcard_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: auth_smartcard_allow -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2(1), IA-2(12), IA-2(2)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: auth_smartcard_allow ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowSmartCard = 1')
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print auth_smartcard_allow:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print auth_smartcard_allow:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) auth_smartcard_allow passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" auth_smartcard_allow -dict-add finding -bool NO
        else
            echo "$(date -u) auth_smartcard_allow failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" auth_smartcard_allow -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) auth_smartcard_allow has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" auth_smartcard_allow -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) auth_smartcard_allow does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" auth_smartcard_allow -dict-add finding -bool NO
fi
    
#####----- Rule: auth_smartcard_certificate_trust_enforce_moderate -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(2)
# * SC-17
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: auth_smartcard_certificate_trust_enforce_moderate ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/awk '/checkCertificateTrust/{print substr($3, 1, length($3)-1)}')
    # expected result {'integer': 2}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print auth_smartcard_certificate_trust_enforce_moderate:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print auth_smartcard_certificate_trust_enforce_moderate:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "2" ]]; then
            echo "$(date -u) auth_smartcard_certificate_trust_enforce_moderate passed (Result: $result_value, Expected: "{'integer': 2}")" | tee -a "$audit_log"
            defaults write "$audit_plist" auth_smartcard_certificate_trust_enforce_moderate -dict-add finding -bool NO
        else
            echo "$(date -u) auth_smartcard_certificate_trust_enforce_moderate failed (Result: $result_value, Expected: "{'integer': 2}")" | tee -a "$audit_log"
            defaults write "$audit_plist" auth_smartcard_certificate_trust_enforce_moderate -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) auth_smartcard_certificate_trust_enforce_moderate has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" auth_smartcard_certificate_trust_enforce_moderate -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) auth_smartcard_certificate_trust_enforce_moderate does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" auth_smartcard_certificate_trust_enforce_moderate -dict-add finding -bool NO
fi
    
#####----- Rule: auth_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2, IA-2(1), IA-2(12), IA-2(2), IA-2(6), IA-2(8)
# * IA-5(2)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: auth_smartcard_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'enforceSmartCard = 1')
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print auth_smartcard_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print auth_smartcard_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) auth_smartcard_enforce passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" auth_smartcard_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) auth_smartcard_enforce failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" auth_smartcard_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) auth_smartcard_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" auth_smartcard_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) auth_smartcard_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" auth_smartcard_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: auth_ssh_password_authentication_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2, IA-2(1), IA-2(2), IA-2(6), IA-2(8)
# * IA-5(2)
# * MA-4
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: auth_ssh_password_authentication_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/grep -Ec '^(PasswordAuthentication\s+no|ChallengeResponseAuthentication\s+no)' /etc/ssh/sshd_config)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print auth_ssh_password_authentication_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print auth_ssh_password_authentication_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) auth_ssh_password_authentication_disable passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" auth_ssh_password_authentication_disable -dict-add finding -bool NO
        else
            echo "$(date -u) auth_ssh_password_authentication_disable failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" auth_ssh_password_authentication_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) auth_ssh_password_authentication_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" auth_ssh_password_authentication_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) auth_ssh_password_authentication_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" auth_ssh_password_authentication_disable -dict-add finding -bool NO
fi
    
#####----- Rule: audit_acls_files_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
# * SI-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_acls_files_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/ls -le $(/usr/bin/awk -F: '/^dir/{print $2}' /etc/security/audit_control) | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":")
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_acls_files_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_acls_files_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) audit_acls_files_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_acls_files_configure -dict-add finding -bool NO
        else
            echo "$(date -u) audit_acls_files_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_acls_files_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_acls_files_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_acls_files_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_acls_files_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_acls_files_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_acls_folders_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_acls_folders_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/ls -lde $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":")
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_acls_folders_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_acls_folders_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) audit_acls_folders_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_acls_folders_configure -dict-add finding -bool NO
        else
            echo "$(date -u) audit_acls_folders_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_acls_folders_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_acls_folders_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_acls_folders_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_acls_folders_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_acls_folders_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_auditd_enabled -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12, AU-12(1), AU-12(3)
# * AU-14(1)
# * AU-3, AU-3(1)
# * AU-8
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_auditd_enabled ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl list | /usr/bin/grep -c com.apple.auditd)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_auditd_enabled:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_auditd_enabled:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) audit_auditd_enabled passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_auditd_enabled -dict-add finding -bool NO
        else
            echo "$(date -u) audit_auditd_enabled failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_auditd_enabled -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_auditd_enabled has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_auditd_enabled -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_auditd_enabled does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_auditd_enabled -dict-add finding -bool NO
fi
    
#####----- Rule: audit_failure_halt -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-5
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_failure_halt ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^policy/ {print $NF}' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'ahlt')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_failure_halt:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_failure_halt:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) audit_failure_halt passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_failure_halt -dict-add finding -bool NO
        else
            echo "$(date -u) audit_failure_halt failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_failure_halt -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_failure_halt has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_failure_halt -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_failure_halt does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_failure_halt -dict-add finding -bool NO
fi
    
#####----- Rule: audit_files_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_files_group_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$4} END {print s}')
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_files_group_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_files_group_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) audit_files_group_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_files_group_configure -dict-add finding -bool NO
        else
            echo "$(date -u) audit_files_group_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_files_group_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_files_group_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_files_group_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_files_group_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_files_group_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_files_mode_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_files_mode_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/ls -l $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '!/-r--r-----|current|total/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' ')
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_files_mode_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_files_mode_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) audit_files_mode_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_files_mode_configure -dict-add finding -bool NO
        else
            echo "$(date -u) audit_files_mode_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_files_mode_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_files_mode_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_files_mode_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_files_mode_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_files_mode_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_files_owner_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_files_owner_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$3} END {print s}')
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_files_owner_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_files_owner_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) audit_files_owner_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_files_owner_configure -dict-add finding -bool NO
        else
            echo "$(date -u) audit_files_owner_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_files_owner_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_files_owner_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_files_owner_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_files_owner_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_files_owner_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_aa_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_aa_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'aa')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_flags_aa_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_flags_aa_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) audit_flags_aa_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_flags_aa_configure -dict-add finding -bool NO
        else
            echo "$(date -u) audit_flags_aa_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_flags_aa_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_flags_aa_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_flags_aa_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_flags_aa_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_aa_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_ad_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12), AC-2(4)
# * AC-6(9)
# * AU-12
# * AU-2
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_ad_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'ad')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_flags_ad_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_flags_ad_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) audit_flags_ad_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_flags_ad_configure -dict-add finding -bool NO
        else
            echo "$(date -u) audit_flags_ad_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_flags_ad_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_flags_ad_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_flags_ad_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_flags_ad_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_ad_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_ex_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * CM-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_ex_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-ex')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_flags_ex_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_flags_ex_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) audit_flags_ex_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_flags_ex_configure -dict-add finding -bool NO
        else
            echo "$(date -u) audit_flags_ex_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_flags_ex_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_flags_ex_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_flags_ex_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_flags_ex_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_ex_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_fd_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_fd_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fd')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_flags_fd_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_flags_fd_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) audit_flags_fd_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_flags_fd_configure -dict-add finding -bool NO
        else
            echo "$(date -u) audit_flags_fd_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_flags_fd_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_flags_fd_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_flags_fd_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_flags_fd_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_fd_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_fm_failed_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_fm_failed_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fm')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_flags_fm_failed_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_flags_fm_failed_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) audit_flags_fm_failed_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_flags_fm_failed_configure -dict-add finding -bool NO
        else
            echo "$(date -u) audit_flags_fm_failed_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_flags_fm_failed_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_flags_fm_failed_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_flags_fm_failed_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_flags_fm_failed_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_fm_failed_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_fr_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_fr_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fr')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_flags_fr_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_flags_fr_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) audit_flags_fr_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_flags_fr_configure -dict-add finding -bool NO
        else
            echo "$(date -u) audit_flags_fr_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_flags_fr_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_flags_fr_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_flags_fr_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_flags_fr_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_fr_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_fw_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_fw_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fw')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_flags_fw_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_flags_fw_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) audit_flags_fw_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_flags_fw_configure -dict-add finding -bool NO
        else
            echo "$(date -u) audit_flags_fw_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_flags_fw_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_flags_fw_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_flags_fw_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_flags_fw_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_fw_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_lo_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17(1)
# * AC-2(12)
# * AU-12
# * AU-2
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_lo_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'lo')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_flags_lo_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_flags_lo_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) audit_flags_lo_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_flags_lo_configure -dict-add finding -bool NO
        else
            echo "$(date -u) audit_flags_lo_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_flags_lo_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_flags_lo_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_flags_lo_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_flags_lo_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_lo_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_folder_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_folder_group_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $4}')
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_folder_group_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_folder_group_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) audit_folder_group_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_folder_group_configure -dict-add finding -bool NO
        else
            echo "$(date -u) audit_folder_group_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_folder_group_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_folder_group_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_folder_group_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_folder_group_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_folder_group_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_folder_owner_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_folder_owner_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $3}')
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_folder_owner_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_folder_owner_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) audit_folder_owner_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_folder_owner_configure -dict-add finding -bool NO
        else
            echo "$(date -u) audit_folder_owner_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_folder_owner_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_folder_owner_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_folder_owner_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_folder_owner_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_folder_owner_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_folders_mode_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_folders_mode_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/stat -f %A $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}'))
    # expected result {'integer': 700}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_folders_mode_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_folders_mode_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "700" ]]; then
            echo "$(date -u) audit_folders_mode_configure passed (Result: $result_value, Expected: "{'integer': 700}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_folders_mode_configure -dict-add finding -bool NO
        else
            echo "$(date -u) audit_folders_mode_configure failed (Result: $result_value, Expected: "{'integer': 700}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_folders_mode_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_folders_mode_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_folders_mode_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_folders_mode_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_folders_mode_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_retention_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-11
# * AU-4
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_retention_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F: '/expire-after/{print $2}' /etc/security/audit_control)
    # expected result {'string': '365d'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_retention_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_retention_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "365d" ]]; then
            echo "$(date -u) audit_retention_configure passed (Result: $result_value, Expected: "{'string': '365d'}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_retention_configure -dict-add finding -bool NO
        else
            echo "$(date -u) audit_retention_configure failed (Result: $result_value, Expected: "{'string': '365d'}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_retention_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_retention_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_retention_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_retention_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_retention_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_settings_failure_notify -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-5, AU-5(2)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_settings_failure_notify ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/grep -c "logger -s -p" /etc/security/audit_warn)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print audit_settings_failure_notify:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print audit_settings_failure_notify:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) audit_settings_failure_notify passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_settings_failure_notify -dict-add finding -bool NO
        else
            echo "$(date -u) audit_settings_failure_notify failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" audit_settings_failure_notify -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) audit_settings_failure_notify has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" audit_settings_failure_notify -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) audit_settings_failure_notify does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" audit_settings_failure_notify -dict-add finding -bool NO
fi
    
#####----- Rule: os_airdrop_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * AC-3
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_airdrop_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowAirDrop = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_airdrop_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_airdrop_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_airdrop_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_airdrop_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_airdrop_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_airdrop_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_airdrop_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_airdrop_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_airdrop_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_airdrop_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_appleid_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_appleid_prompt_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SkipCloudSetup = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_appleid_prompt_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_appleid_prompt_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_appleid_prompt_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_appleid_prompt_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_appleid_prompt_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_appleid_prompt_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_appleid_prompt_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_appleid_prompt_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_appleid_prompt_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_appleid_prompt_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_asl_log_files_owner_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_asl_log_files_owner_group_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/stat -f '%Su:%Sg:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print $2 }') 2> /dev/null | /usr/bin/awk '!/^root:wheel:/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' ')
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_asl_log_files_owner_group_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_asl_log_files_owner_group_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) os_asl_log_files_owner_group_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_asl_log_files_owner_group_configure -dict-add finding -bool NO
        else
            echo "$(date -u) os_asl_log_files_owner_group_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_asl_log_files_owner_group_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_asl_log_files_owner_group_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_asl_log_files_owner_group_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_asl_log_files_owner_group_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_asl_log_files_owner_group_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_asl_log_files_permissions_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_asl_log_files_permissions_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/stat -f '%A:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print $2 }') 2> /dev/null | /usr/bin/awk '!/640/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' ')
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_asl_log_files_permissions_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_asl_log_files_permissions_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) os_asl_log_files_permissions_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_asl_log_files_permissions_configure -dict-add finding -bool NO
        else
            echo "$(date -u) os_asl_log_files_permissions_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_asl_log_files_permissions_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_asl_log_files_permissions_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_asl_log_files_permissions_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_asl_log_files_permissions_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_asl_log_files_permissions_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_authenticated_root_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-3
# * CM-5
# * MA-4(1)
# * SC-34
# * SI-7, SI-7(6)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_authenticated_root_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/csrutil authenticated-root | /usr/bin/grep -c 'enabled')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_authenticated_root_enable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_authenticated_root_enable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_authenticated_root_enable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_authenticated_root_enable -dict-add finding -bool NO
        else
            echo "$(date -u) os_authenticated_root_enable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_authenticated_root_enable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_authenticated_root_enable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_authenticated_root_enable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_authenticated_root_enable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_authenticated_root_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_bonjour_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_bonjour_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'NoMulticastAdvertisements = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_bonjour_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_bonjour_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_bonjour_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_bonjour_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_bonjour_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_bonjour_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_bonjour_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_bonjour_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_bonjour_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_bonjour_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_calendar_app_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_calendar_app_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -A 20 familyControlsEnabled | /usr/bin/grep -c "/Applications/Calendar.app")
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_calendar_app_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_calendar_app_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_calendar_app_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_calendar_app_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_calendar_app_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_calendar_app_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_calendar_app_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_calendar_app_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_calendar_app_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_calendar_app_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_config_data_install_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-2(5)
# * SI-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_config_data_install_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'ConfigDataInstall = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_config_data_install_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_config_data_install_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_config_data_install_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_config_data_install_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) os_config_data_install_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_config_data_install_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_config_data_install_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_config_data_install_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_config_data_install_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_config_data_install_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: os_facetime_app_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_facetime_app_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -A 20 familyControlsEnabled | /usr/bin/grep -c "/Applications/FaceTime.app")
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_facetime_app_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_facetime_app_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_facetime_app_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_facetime_app_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_facetime_app_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_facetime_app_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_facetime_app_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_facetime_app_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_facetime_app_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_facetime_app_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_filevault_autologin_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(11)
# * AC-3
# * IA-5(13)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_filevault_autologin_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'DisableFDEAutoLogin = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_filevault_autologin_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_filevault_autologin_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_filevault_autologin_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_filevault_autologin_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_filevault_autologin_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_filevault_autologin_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_filevault_autologin_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_filevault_autologin_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_filevault_autologin_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_filevault_autologin_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_firewall_default_deny_require -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-4
# * SC-7(5)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_firewall_default_deny_require ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/sbin/pfctl -a '*' -sr &> /dev/null | /usr/bin/grep -c "block drop in all")
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_firewall_default_deny_require:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_firewall_default_deny_require:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_firewall_default_deny_require passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_firewall_default_deny_require -dict-add finding -bool NO
        else
            echo "$(date -u) os_firewall_default_deny_require failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_firewall_default_deny_require -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_firewall_default_deny_require has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_firewall_default_deny_require -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_firewall_default_deny_require does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_firewall_default_deny_require -dict-add finding -bool NO
fi
    
#####----- Rule: os_firewall_log_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12
# * SC-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_firewall_log_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '(EnableLogging = 1|LoggingOption = detail)')
    # expected result {'integer': 2}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_firewall_log_enable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_firewall_log_enable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "2" ]]; then
            echo "$(date -u) os_firewall_log_enable passed (Result: $result_value, Expected: "{'integer': 2}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_firewall_log_enable -dict-add finding -bool NO
        else
            echo "$(date -u) os_firewall_log_enable failed (Result: $result_value, Expected: "{'integer': 2}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_firewall_log_enable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_firewall_log_enable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_firewall_log_enable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_firewall_log_enable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_firewall_log_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_firmware_password_require -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-6
#  intel chip = i386
#  m2 chip = arm64
# Not applicable to apple silicon, only used for intel
rule_arch="i386"
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_firmware_password_require ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/sbin/firmwarepasswd -check | /usr/bin/grep -c "Password Enabled: Yes")
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_firmware_password_require:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_firmware_password_require:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_firmware_password_require passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_firmware_password_require -dict-add finding -bool NO
        else
            echo "$(date -u) os_firmware_password_require failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_firmware_password_require -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_firmware_password_require has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_firmware_password_require -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_firmware_password_require does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_firmware_password_require -dict-add finding -bool NO
fi
    
#####----- Rule: os_gatekeeper_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-14
# * CM-5
# * SI-3
# * SI-7(1), SI-7(15)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_gatekeeper_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/sbin/spctl --status | /usr/bin/grep -c "assessments enabled")
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_gatekeeper_enable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_gatekeeper_enable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_gatekeeper_enable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_gatekeeper_enable -dict-add finding -bool NO
        else
            echo "$(date -u) os_gatekeeper_enable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_gatekeeper_enable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_gatekeeper_enable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_gatekeeper_enable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_gatekeeper_enable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_gatekeeper_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_gatekeeper_rearm -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-5
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_gatekeeper_rearm ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'GKAutoRearm = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_gatekeeper_rearm:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_gatekeeper_rearm:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_gatekeeper_rearm passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_gatekeeper_rearm -dict-add finding -bool NO
        else
            echo "$(date -u) os_gatekeeper_rearm failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_gatekeeper_rearm -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_gatekeeper_rearm has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_gatekeeper_rearm -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_gatekeeper_rearm does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_gatekeeper_rearm -dict-add finding -bool NO
fi
    
#####----- Rule: os_handoff_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * AC-3
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_handoff_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowActivityContinuation = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_handoff_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_handoff_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_handoff_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_handoff_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_handoff_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_handoff_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_handoff_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_handoff_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_handoff_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_handoff_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_home_folders_secure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-6
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_home_folders_secure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d -perm -1 | /usr/bin/grep -v "Shared" | /usr/bin/grep -v "Guest" | /usr/bin/wc -l | /usr/bin/xargs)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_home_folders_secure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_home_folders_secure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) os_home_folders_secure passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_home_folders_secure -dict-add finding -bool NO
        else
            echo "$(date -u) os_home_folders_secure failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_home_folders_secure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_home_folders_secure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_home_folders_secure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_home_folders_secure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_home_folders_secure -dict-add finding -bool NO
fi
    
#####----- Rule: os_httpd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_httpd_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"org.apache.httpd" => true')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_httpd_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_httpd_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_httpd_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_httpd_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_httpd_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_httpd_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_httpd_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_httpd_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_httpd_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_httpd_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_icloud_storage_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_icloud_storage_prompt_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SkipiCloudStorageSetup = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_icloud_storage_prompt_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_icloud_storage_prompt_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_icloud_storage_prompt_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_icloud_storage_prompt_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_icloud_storage_prompt_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_icloud_storage_prompt_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_icloud_storage_prompt_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_icloud_storage_prompt_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_icloud_storage_prompt_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_icloud_storage_prompt_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_internet_accounts_prefpane_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7(5)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_internet_accounts_prefpane_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'com.apple.preferences.internetaccounts')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_internet_accounts_prefpane_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_internet_accounts_prefpane_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_internet_accounts_prefpane_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_internet_accounts_prefpane_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_internet_accounts_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_internet_accounts_prefpane_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_internet_accounts_prefpane_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_internet_accounts_prefpane_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_internet_accounts_prefpane_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_internet_accounts_prefpane_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_ir_support_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-18
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_ir_support_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'DeviceEnabled = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_ir_support_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_ir_support_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_ir_support_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_ir_support_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_ir_support_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_ir_support_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_ir_support_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_ir_support_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_ir_support_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_ir_support_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_mail_app_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_mail_app_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -A 20 familyControlsEnabled | /usr/bin/grep -c "/Applications/Mail.app")
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_mail_app_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_mail_app_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_mail_app_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_mail_app_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_mail_app_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_mail_app_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_mail_app_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_mail_app_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_mail_app_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_mail_app_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_mdm_require -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-2
# * CM-6
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_mdm_require ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles status -type enrollment | /usr/bin/awk -F: '/MDM enrollment/ {print $2}' | /usr/bin/grep -c "Yes (User Approved)")
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_mdm_require:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_mdm_require:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_mdm_require passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_mdm_require -dict-add finding -bool NO
        else
            echo "$(date -u) os_mdm_require failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_mdm_require -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_mdm_require has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_mdm_require -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_mdm_require does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_mdm_require -dict-add finding -bool NO
fi
    
#####----- Rule: os_messages_app_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_messages_app_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -A 20 familyControlsEnabled | /usr/bin/grep -c "/Applications/Messages.app")
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_messages_app_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_messages_app_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_messages_app_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_messages_app_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_messages_app_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_messages_app_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_messages_app_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_messages_app_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_messages_app_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_messages_app_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_newsyslog_files_owner_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_newsyslog_files_owner_group_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/stat -f '%Su:%Sg:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print $1 }') 2> /dev/null | /usr/bin/awk '!/^root:wheel:/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' ')
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_newsyslog_files_owner_group_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_newsyslog_files_owner_group_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) os_newsyslog_files_owner_group_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_newsyslog_files_owner_group_configure -dict-add finding -bool NO
        else
            echo "$(date -u) os_newsyslog_files_owner_group_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_newsyslog_files_owner_group_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_newsyslog_files_owner_group_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_newsyslog_files_owner_group_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_newsyslog_files_owner_group_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_newsyslog_files_owner_group_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_newsyslog_files_permissions_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_newsyslog_files_permissions_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/stat -f '%A:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print $1 }') 2> /dev/null | /usr/bin/awk '!/640/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' ')
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_newsyslog_files_permissions_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_newsyslog_files_permissions_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) os_newsyslog_files_permissions_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_newsyslog_files_permissions_configure -dict-add finding -bool NO
        else
            echo "$(date -u) os_newsyslog_files_permissions_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_newsyslog_files_permissions_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_newsyslog_files_permissions_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_newsyslog_files_permissions_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_newsyslog_files_permissions_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_newsyslog_files_permissions_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_nfsd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_nfsd_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.nfsd" => true')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_nfsd_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_nfsd_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_nfsd_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_nfsd_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_nfsd_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_nfsd_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_nfsd_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_nfsd_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_nfsd_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_nfsd_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_parental_controls_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7(2)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_parental_controls_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'familyControlsEnabled = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_parental_controls_enable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_parental_controls_enable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_parental_controls_enable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_parental_controls_enable -dict-add finding -bool NO
        else
            echo "$(date -u) os_parental_controls_enable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_parental_controls_enable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_parental_controls_enable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_parental_controls_enable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_parental_controls_enable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_parental_controls_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_password_autofill_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
# * IA-11
# * IA-5, IA-5(13)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_password_autofill_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowPasswordAutoFill = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_password_autofill_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_password_autofill_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_password_autofill_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_password_autofill_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_password_autofill_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_password_autofill_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_password_autofill_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_password_autofill_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_password_autofill_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_password_autofill_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_password_proximity_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_password_proximity_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowPasswordProximityRequests = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_password_proximity_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_password_proximity_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_password_proximity_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_password_proximity_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_password_proximity_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_password_proximity_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_password_proximity_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_password_proximity_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_password_proximity_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_password_proximity_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_password_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_password_sharing_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowPasswordSharing = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_password_sharing_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_password_sharing_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_password_sharing_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_password_sharing_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_password_sharing_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_password_sharing_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_password_sharing_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_password_sharing_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_password_sharing_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_password_sharing_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_policy_banner_loginwindow_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-8
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_policy_banner_loginwindow_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/ls -ld /Library/Security/PolicyBanner.rtf* | /usr/bin/wc -l | /usr/bin/tr -d ' ')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_policy_banner_loginwindow_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_policy_banner_loginwindow_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_policy_banner_loginwindow_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_policy_banner_loginwindow_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) os_policy_banner_loginwindow_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_policy_banner_loginwindow_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_policy_banner_loginwindow_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_policy_banner_loginwindow_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_policy_banner_loginwindow_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_policy_banner_loginwindow_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: os_recovery_lock_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-6
rule_arch="arm64"
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_recovery_lock_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c "IsRecoveryLockedEnabled = 1")
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_recovery_lock_enable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_recovery_lock_enable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_recovery_lock_enable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_recovery_lock_enable -dict-add finding -bool NO
        else
            echo "$(date -u) os_recovery_lock_enable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_recovery_lock_enable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_recovery_lock_enable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_recovery_lock_enable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_recovery_lock_enable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_recovery_lock_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_removable_media_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * MP-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_removable_media_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep 'harddisk-external' -A3 | /usr/bin/grep -Ec "eject|alert")
    # expected result {'integer': 2}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_removable_media_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_removable_media_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "2" ]]; then
            echo "$(date -u) os_removable_media_disable passed (Result: $result_value, Expected: "{'integer': 2}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_removable_media_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_removable_media_disable failed (Result: $result_value, Expected: "{'integer': 2}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_removable_media_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_removable_media_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_removable_media_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_removable_media_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_removable_media_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_root_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2, IA-2(5)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_root_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/dscl . -read /Users/root UserShell 2>&1 | /usr/bin/grep -c "/usr/bin/false")
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_root_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_root_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_root_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_root_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_root_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_root_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_root_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_root_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_root_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_root_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_screensaver_loginwindow_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_screensaver_loginwindow_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout  | /usr/bin/grep -c loginWindowModulePath)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_screensaver_loginwindow_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_screensaver_loginwindow_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_screensaver_loginwindow_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_screensaver_loginwindow_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) os_screensaver_loginwindow_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_screensaver_loginwindow_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_screensaver_loginwindow_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_screensaver_loginwindow_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_screensaver_loginwindow_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_screensaver_loginwindow_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: os_secure_boot_verify -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-6
# * SI-7, SI-7(1), SI-7(5)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_secure_boot_verify ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c "SecureBootLevel = full")
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_secure_boot_verify:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_secure_boot_verify:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_secure_boot_verify passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_secure_boot_verify -dict-add finding -bool NO
        else
            echo "$(date -u) os_secure_boot_verify failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_secure_boot_verify -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_secure_boot_verify has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_secure_boot_verify -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_secure_boot_verify does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_secure_boot_verify -dict-add finding -bool NO
fi
    
#####----- Rule: os_sip_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-3
# * AU-9, AU-9(3)
# * CM-5, CM-5(6)
# * SC-4
# * SI-2
# * SI-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_sip_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/csrutil status | /usr/bin/grep -c 'System Integrity Protection status: enabled.')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_sip_enable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_sip_enable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_sip_enable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_sip_enable -dict-add finding -bool NO
        else
            echo "$(date -u) os_sip_enable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_sip_enable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_sip_enable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_sip_enable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_sip_enable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_sip_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_siri_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_siri_prompt_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SkipSiriSetup = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_siri_prompt_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_siri_prompt_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_siri_prompt_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_siri_prompt_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_siri_prompt_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_siri_prompt_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_siri_prompt_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_siri_prompt_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_siri_prompt_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_siri_prompt_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_skip_unlock_with_watch_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_skip_unlock_with_watch_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SkipUnlockWithWatch = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_skip_unlock_with_watch_enable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_skip_unlock_with_watch_enable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_skip_unlock_with_watch_enable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_skip_unlock_with_watch_enable -dict-add finding -bool NO
        else
            echo "$(date -u) os_skip_unlock_with_watch_enable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_skip_unlock_with_watch_enable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_skip_unlock_with_watch_enable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_skip_unlock_with_watch_enable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_skip_unlock_with_watch_enable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_skip_unlock_with_watch_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_ssh_fips_compliant -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17(2)
# * IA-7
# * SC-13
# * SC-8(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_ssh_fips_compliant ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(fips_ssh_config="Host *
Ciphers aes128-gcm@openssh.com
HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
KexAlgorithms ecdh-sha2-nistp256
MACs hmac-sha2-256
PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
CASignatureAlgorithms ecdsa-sha2-nistp256"
/usr/bin/grep -c "$fips_ssh_config" /etc/ssh/ssh_config.d/fips_ssh_config)
    # expected result {'integer': 8}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_ssh_fips_compliant:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_ssh_fips_compliant:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "8" ]]; then
            echo "$(date -u) os_ssh_fips_compliant passed (Result: $result_value, Expected: "{'integer': 8}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_ssh_fips_compliant -dict-add finding -bool NO
        else
            echo "$(date -u) os_ssh_fips_compliant failed (Result: $result_value, Expected: "{'integer': 8}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_ssh_fips_compliant -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_ssh_fips_compliant has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_ssh_fips_compliant -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_ssh_fips_compliant does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_ssh_fips_compliant -dict-add finding -bool NO
fi
    
#####----- Rule: os_ssh_server_alive_count_max_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SC-10
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_ssh_server_alive_count_max_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/grep -c "^ServerAliveCountMax 0" /etc/ssh/ssh_config)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_ssh_server_alive_count_max_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_ssh_server_alive_count_max_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_ssh_server_alive_count_max_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_ssh_server_alive_count_max_configure -dict-add finding -bool NO
        else
            echo "$(date -u) os_ssh_server_alive_count_max_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_ssh_server_alive_count_max_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_ssh_server_alive_count_max_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_ssh_server_alive_count_max_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_ssh_server_alive_count_max_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_ssh_server_alive_count_max_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_ssh_server_alive_interval_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-12
# * SC-10
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_ssh_server_alive_interval_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/grep -c "^ServerAliveInterval 900" /etc/ssh/ssh_config)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_ssh_server_alive_interval_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_ssh_server_alive_interval_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_ssh_server_alive_interval_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_ssh_server_alive_interval_configure -dict-add finding -bool NO
        else
            echo "$(date -u) os_ssh_server_alive_interval_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_ssh_server_alive_interval_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_ssh_server_alive_interval_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_ssh_server_alive_interval_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_ssh_server_alive_interval_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_ssh_server_alive_interval_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_sshd_fips_compliant -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17(2)
# * IA-7
# * SC-13
# * SC-8(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_sshd_fips_compliant ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(fips_sshd_config="Ciphers aes128-gcm@openssh.com
HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
KexAlgorithms ecdh-sha2-nistp256
MACs hmac-sha2-256
PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
CASignatureAlgorithms ecdsa-sha2-nistp256"
/usr/bin/grep -c "$fips_sshd_config" /etc/ssh/sshd_config.d/fips_sshd_config)
    # expected result {'integer': 7}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_sshd_fips_compliant:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_sshd_fips_compliant:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "7" ]]; then
            echo "$(date -u) os_sshd_fips_compliant passed (Result: $result_value, Expected: "{'integer': 7}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_sshd_fips_compliant -dict-add finding -bool NO
        else
            echo "$(date -u) os_sshd_fips_compliant failed (Result: $result_value, Expected: "{'integer': 7}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_sshd_fips_compliant -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_sshd_fips_compliant has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_sshd_fips_compliant -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_sshd_fips_compliant does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_sshd_fips_compliant -dict-add finding -bool NO
fi
    
#####----- Rule: os_sudoers_tty_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-5(1)
# * IA-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_sudoers_tty_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/grep -Ec "^Defaults tty_tickets" /etc/sudoers)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_sudoers_tty_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_sudoers_tty_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_sudoers_tty_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_sudoers_tty_configure -dict-add finding -bool NO
        else
            echo "$(date -u) os_sudoers_tty_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_sudoers_tty_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_sudoers_tty_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_sudoers_tty_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_sudoers_tty_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_sudoers_tty_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_system_read_only -----#####
## Addresses the following NIST 800-53 controls: 
# * MA-4(1)
# * SC-34
# * SI-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_system_read_only ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/sbin/system_profiler SPStorageDataType | /usr/bin/awk '/Mount Point: \/$/{x=NR+2}(NR==x){print $2}')
    # expected result {'string': 'No'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_system_read_only:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_system_read_only:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "No" ]]; then
            echo "$(date -u) os_system_read_only passed (Result: $result_value, Expected: "{'string': 'No'}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_system_read_only -dict-add finding -bool NO
        else
            echo "$(date -u) os_system_read_only failed (Result: $result_value, Expected: "{'string': 'No'}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_system_read_only -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_system_read_only has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_system_read_only -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_system_read_only does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_system_read_only -dict-add finding -bool NO
fi
    
#####----- Rule: os_tftpd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_tftpd_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.tftpd" => true')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_tftpd_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_tftpd_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_tftpd_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_tftpd_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_tftpd_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_tftpd_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_tftpd_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_tftpd_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_tftpd_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_tftpd_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_time_server_enabled -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12(1)
# * SC-45(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_time_server_enabled ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl list | /usr/bin/grep -c com.apple.timed)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_time_server_enabled:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_time_server_enabled:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_time_server_enabled passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_time_server_enabled -dict-add finding -bool NO
        else
            echo "$(date -u) os_time_server_enabled failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_time_server_enabled -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_time_server_enabled has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_time_server_enabled -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_time_server_enabled does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_time_server_enabled -dict-add finding -bool NO
fi
    
#####----- Rule: os_touchid_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-6
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_touchid_prompt_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SkipTouchIDSetup = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_touchid_prompt_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_touchid_prompt_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_touchid_prompt_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_touchid_prompt_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_touchid_prompt_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_touchid_prompt_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_touchid_prompt_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_touchid_prompt_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_touchid_prompt_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_touchid_prompt_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_unlock_active_user_session_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2, IA-2(5)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_unlock_active_user_session_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/security authorizationdb read system.login.screensaver 2>&1 | /usr/bin/grep -c 'use-login-window-ui')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_unlock_active_user_session_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_unlock_active_user_session_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_unlock_active_user_session_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_unlock_active_user_session_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_unlock_active_user_session_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_unlock_active_user_session_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_unlock_active_user_session_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_unlock_active_user_session_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_unlock_active_user_session_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_unlock_active_user_session_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_uucp_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_uucp_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.uucp" => true')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print os_uucp_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print os_uucp_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) os_uucp_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_uucp_disable -dict-add finding -bool NO
        else
            echo "$(date -u) os_uucp_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" os_uucp_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) os_uucp_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" os_uucp_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) os_uucp_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" os_uucp_disable -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_60_day_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_60_day_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/awk -F " = " '/maxPINAgeInDays/{sub(/;.*/,"");print $2}')
    # expected result {'integer': 90}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print pwpolicy_60_day_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print pwpolicy_60_day_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "90" ]]; then
            echo "$(date -u) pwpolicy_60_day_enforce passed (Result: $result_value, Expected: "{'integer': 90}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_60_day_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) pwpolicy_60_day_enforce failed (Result: $result_value, Expected: "{'integer': 90}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_60_day_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) pwpolicy_60_day_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" pwpolicy_60_day_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) pwpolicy_60_day_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_60_day_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_account_inactivity_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(3)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_account_inactivity_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy getaccountpolicies | /usr/bin/grep -v "Getting global account policies" | /usr/bin/xmllint --xpath '/plist/dict/array/dict/dict[key="policyAttributeInactiveDays"]/integer' - | /usr/bin/awk -F '[<>]' '{print $3}')
    # expected result {'integer': 35}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print pwpolicy_account_inactivity_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print pwpolicy_account_inactivity_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "35" ]]; then
            echo "$(date -u) pwpolicy_account_inactivity_enforce passed (Result: $result_value, Expected: "{'integer': 35}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_account_inactivity_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) pwpolicy_account_inactivity_enforce failed (Result: $result_value, Expected: "{'integer': 35}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_account_inactivity_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) pwpolicy_account_inactivity_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" pwpolicy_account_inactivity_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) pwpolicy_account_inactivity_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_account_inactivity_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_account_lockout_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_account_lockout_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'maxFailedAttempts = 5')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print pwpolicy_account_lockout_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print pwpolicy_account_lockout_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) pwpolicy_account_lockout_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_account_lockout_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) pwpolicy_account_lockout_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_account_lockout_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) pwpolicy_account_lockout_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" pwpolicy_account_lockout_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) pwpolicy_account_lockout_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_account_lockout_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_account_lockout_timeout_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_account_lockout_timeout_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'minutesUntilFailedLoginReset = 30')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print pwpolicy_account_lockout_timeout_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print pwpolicy_account_lockout_timeout_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) pwpolicy_account_lockout_timeout_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_account_lockout_timeout_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) pwpolicy_account_lockout_timeout_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_account_lockout_timeout_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) pwpolicy_account_lockout_timeout_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" pwpolicy_account_lockout_timeout_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) pwpolicy_account_lockout_timeout_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_account_lockout_timeout_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_alpha_numeric_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_alpha_numeric_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c "requireAlphanumeric = 1;")
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print pwpolicy_alpha_numeric_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print pwpolicy_alpha_numeric_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) pwpolicy_alpha_numeric_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_alpha_numeric_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) pwpolicy_alpha_numeric_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_alpha_numeric_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) pwpolicy_alpha_numeric_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" pwpolicy_alpha_numeric_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) pwpolicy_alpha_numeric_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_alpha_numeric_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_history_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_history_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/awk '/pinHistory/{sub(/;.*/,"");print $3}')
    # expected result {'integer': 5}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print pwpolicy_history_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print pwpolicy_history_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "5" ]]; then
            echo "$(date -u) pwpolicy_history_enforce passed (Result: $result_value, Expected: "{'integer': 5}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_history_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) pwpolicy_history_enforce failed (Result: $result_value, Expected: "{'integer': 5}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_history_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) pwpolicy_history_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" pwpolicy_history_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) pwpolicy_history_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_history_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_lower_case_character_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_lower_case_character_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy getaccountpolicies | /usr/bin/grep -v "Getting global account policies" | /usr/bin/xmllint --xpath '/plist/dict/array/dict/dict[key="minimumAlphaCharactersLowerCase"]/integer' - | /usr/bin/awk -F '[<>]' '{print $3}')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print pwpolicy_lower_case_character_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print pwpolicy_lower_case_character_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) pwpolicy_lower_case_character_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_lower_case_character_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) pwpolicy_lower_case_character_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_lower_case_character_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) pwpolicy_lower_case_character_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" pwpolicy_lower_case_character_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) pwpolicy_lower_case_character_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_lower_case_character_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_minimum_length_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_minimum_length_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'minLength = 16')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print pwpolicy_minimum_length_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print pwpolicy_minimum_length_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) pwpolicy_minimum_length_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_minimum_length_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) pwpolicy_minimum_length_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_minimum_length_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) pwpolicy_minimum_length_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" pwpolicy_minimum_length_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) pwpolicy_minimum_length_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_minimum_length_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_minimum_lifetime_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_minimum_lifetime_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy getaccountpolicies | /usr/bin/grep -v "Getting global account policies" | /usr/bin/xmllint --xpath '/plist/dict/array/dict/dict[key="policyAttributeMinimumLifetimeHours"]/integer' - | /usr/bin/awk -F '[<>]' '{print $3}')
    # expected result {'integer': 24}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print pwpolicy_minimum_lifetime_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print pwpolicy_minimum_lifetime_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "24" ]]; then
            echo "$(date -u) pwpolicy_minimum_lifetime_enforce passed (Result: $result_value, Expected: "{'integer': 24}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_minimum_lifetime_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) pwpolicy_minimum_lifetime_enforce failed (Result: $result_value, Expected: "{'integer': 24}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_minimum_lifetime_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) pwpolicy_minimum_lifetime_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" pwpolicy_minimum_lifetime_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) pwpolicy_minimum_lifetime_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_minimum_lifetime_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_simple_sequence_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_simple_sequence_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowSimple = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print pwpolicy_simple_sequence_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print pwpolicy_simple_sequence_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) pwpolicy_simple_sequence_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_simple_sequence_disable -dict-add finding -bool NO
        else
            echo "$(date -u) pwpolicy_simple_sequence_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_simple_sequence_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) pwpolicy_simple_sequence_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" pwpolicy_simple_sequence_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) pwpolicy_simple_sequence_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_simple_sequence_disable -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_special_character_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_special_character_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/awk '/minComplexChars/{sub(/;.*/,"");print $3}')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print pwpolicy_special_character_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print pwpolicy_special_character_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) pwpolicy_special_character_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_special_character_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) pwpolicy_special_character_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_special_character_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) pwpolicy_special_character_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" pwpolicy_special_character_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) pwpolicy_special_character_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_special_character_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_upper_case_character_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_upper_case_character_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy getaccountpolicies | /usr/bin/grep -v "Getting global account policies" | /usr/bin/xmllint --xpath '/plist/dict/array/dict/dict[key="minimumAlphaCharactersUpperCase"]/integer' - | /usr/bin/awk -F '[<>]' '{print $3}')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print pwpolicy_upper_case_character_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print pwpolicy_upper_case_character_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) pwpolicy_upper_case_character_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_upper_case_character_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) pwpolicy_upper_case_character_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" pwpolicy_upper_case_character_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) pwpolicy_upper_case_character_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" pwpolicy_upper_case_character_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) pwpolicy_upper_case_character_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_upper_case_character_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_addressbook_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_addressbook_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudAddressBook = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print icloud_addressbook_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print icloud_addressbook_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) icloud_addressbook_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_addressbook_disable -dict-add finding -bool NO
        else
            echo "$(date -u) icloud_addressbook_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_addressbook_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) icloud_addressbook_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" icloud_addressbook_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) icloud_addressbook_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_addressbook_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_appleid_prefpane_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_appleid_prefpane_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'com.apple.preferences.AppleID')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print icloud_appleid_prefpane_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print icloud_appleid_prefpane_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) icloud_appleid_prefpane_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_appleid_prefpane_disable -dict-add finding -bool NO
        else
            echo "$(date -u) icloud_appleid_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_appleid_prefpane_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) icloud_appleid_prefpane_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" icloud_appleid_prefpane_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) icloud_appleid_prefpane_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_appleid_prefpane_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_bookmarks_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_bookmarks_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudBookmarks = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print icloud_bookmarks_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print icloud_bookmarks_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) icloud_bookmarks_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_bookmarks_disable -dict-add finding -bool NO
        else
            echo "$(date -u) icloud_bookmarks_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_bookmarks_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) icloud_bookmarks_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" icloud_bookmarks_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) icloud_bookmarks_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_bookmarks_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_calendar_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_calendar_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudCalendar = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print icloud_calendar_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print icloud_calendar_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) icloud_calendar_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_calendar_disable -dict-add finding -bool NO
        else
            echo "$(date -u) icloud_calendar_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_calendar_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) icloud_calendar_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" icloud_calendar_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) icloud_calendar_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_calendar_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_drive_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_drive_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudDocumentSync = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print icloud_drive_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print icloud_drive_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) icloud_drive_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_drive_disable -dict-add finding -bool NO
        else
            echo "$(date -u) icloud_drive_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_drive_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) icloud_drive_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" icloud_drive_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) icloud_drive_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_drive_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_keychain_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_keychain_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudKeychainSync = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print icloud_keychain_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print icloud_keychain_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) icloud_keychain_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_keychain_disable -dict-add finding -bool NO
        else
            echo "$(date -u) icloud_keychain_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_keychain_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) icloud_keychain_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" icloud_keychain_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) icloud_keychain_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_keychain_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_mail_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_mail_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudMail = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print icloud_mail_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print icloud_mail_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) icloud_mail_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_mail_disable -dict-add finding -bool NO
        else
            echo "$(date -u) icloud_mail_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_mail_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) icloud_mail_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" icloud_mail_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) icloud_mail_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_mail_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_notes_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_notes_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudNotes = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print icloud_notes_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print icloud_notes_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) icloud_notes_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_notes_disable -dict-add finding -bool NO
        else
            echo "$(date -u) icloud_notes_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_notes_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) icloud_notes_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" icloud_notes_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) icloud_notes_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_notes_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_photos_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_photos_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudPhotoLibrary = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print icloud_photos_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print icloud_photos_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) icloud_photos_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_photos_disable -dict-add finding -bool NO
        else
            echo "$(date -u) icloud_photos_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_photos_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) icloud_photos_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" icloud_photos_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) icloud_photos_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_photos_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_private_relay_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_private_relay_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudPrivateRelay = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print icloud_private_relay_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print icloud_private_relay_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) icloud_private_relay_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_private_relay_disable -dict-add finding -bool NO
        else
            echo "$(date -u) icloud_private_relay_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_private_relay_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) icloud_private_relay_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" icloud_private_relay_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) icloud_private_relay_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_private_relay_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_reminders_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_reminders_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudReminders = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print icloud_reminders_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print icloud_reminders_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) icloud_reminders_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_reminders_disable -dict-add finding -bool NO
        else
            echo "$(date -u) icloud_reminders_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_reminders_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) icloud_reminders_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" icloud_reminders_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) icloud_reminders_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_reminders_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_sync_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_sync_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudDesktopAndDocuments = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print icloud_sync_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print icloud_sync_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) icloud_sync_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_sync_disable -dict-add finding -bool NO
        else
            echo "$(date -u) icloud_sync_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" icloud_sync_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) icloud_sync_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" icloud_sync_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) icloud_sync_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_sync_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_airplay_receiver_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_airplay_receiver_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'AirplayRecieverEnabled = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_airplay_receiver_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_airplay_receiver_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_airplay_receiver_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_airplay_receiver_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_airplay_receiver_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_airplay_receiver_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_airplay_receiver_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_airplay_receiver_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_airplay_receiver_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_airplay_receiver_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_apple_watch_unlock_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_apple_watch_unlock_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowAutoUnlock = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_apple_watch_unlock_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_apple_watch_unlock_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_apple_watch_unlock_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_apple_watch_unlock_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_apple_watch_unlock_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_apple_watch_unlock_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_apple_watch_unlock_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_apple_watch_unlock_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_apple_watch_unlock_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_apple_watch_unlock_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_automatic_login_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2
# * IA-5(13)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_automatic_login_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c '"com.apple.login.mcx.DisableAutoLoginClient" = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_automatic_login_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_automatic_login_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_automatic_login_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_automatic_login_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_automatic_login_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_automatic_login_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_automatic_login_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_automatic_login_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_automatic_login_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_automatic_login_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_automatic_logout_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-12
# * AC-2(5)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_automatic_logout_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c '"com.apple.autologout.AutoLogOutDelay" = 86400')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_automatic_logout_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_automatic_logout_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_automatic_logout_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_automatic_logout_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_automatic_logout_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_automatic_logout_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_automatic_logout_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_automatic_logout_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_automatic_logout_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_automatic_logout_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_bluetooth_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-18, AC-18(3)
# * SC-8
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_bluetooth_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'DisableBluetooth = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_bluetooth_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_bluetooth_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_bluetooth_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_bluetooth_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_bluetooth_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_bluetooth_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_bluetooth_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_bluetooth_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_bluetooth_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_bluetooth_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_bluetooth_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-18(4)
# * AC-3
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_bluetooth_sharing_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled)
    # expected result {'boolean': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_bluetooth_sharing_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_bluetooth_sharing_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) sysprefs_bluetooth_sharing_disable passed (Result: $result_value, Expected: "{'boolean': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_bluetooth_sharing_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_bluetooth_sharing_disable failed (Result: $result_value, Expected: "{'boolean': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_bluetooth_sharing_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_bluetooth_sharing_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_bluetooth_sharing_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_bluetooth_sharing_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_bluetooth_sharing_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_content_caching_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_content_caching_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowContentCaching = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_content_caching_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_content_caching_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_content_caching_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_content_caching_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_content_caching_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_content_caching_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_content_caching_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_content_caching_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_content_caching_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_content_caching_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_critical_update_install_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-2
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_critical_update_install_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'CriticalUpdateInstall = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_critical_update_install_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_critical_update_install_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_critical_update_install_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_critical_update_install_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_critical_update_install_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_critical_update_install_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_critical_update_install_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_critical_update_install_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_critical_update_install_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_critical_update_install_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_diagnostics_reports_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * SC-7(10)
# * SI-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_diagnostics_reports_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '(allowDiagnosticSubmission = 0|AutoSubmit = 0)')
    # expected result {'integer': 2}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_diagnostics_reports_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_diagnostics_reports_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "2" ]]; then
            echo "$(date -u) sysprefs_diagnostics_reports_disable passed (Result: $result_value, Expected: "{'integer': 2}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_diagnostics_reports_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_diagnostics_reports_disable failed (Result: $result_value, Expected: "{'integer': 2}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_diagnostics_reports_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_diagnostics_reports_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_diagnostics_reports_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_diagnostics_reports_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_diagnostics_reports_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_filevault_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * SC-28, SC-28(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_filevault_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/fdesetup status | /usr/bin/grep -c "FileVault is On.")
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_filevault_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_filevault_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_filevault_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_filevault_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_filevault_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_filevault_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_filevault_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_filevault_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_filevault_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_filevault_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_find_my_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_find_my_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '(allowFindMyDevice = 0|allowFindMyFriends = 0|DisableFMMiCloudSetting = 1)')
    # expected result {'integer': 3}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_find_my_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_find_my_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "3" ]]; then
            echo "$(date -u) sysprefs_find_my_disable passed (Result: $result_value, Expected: "{'integer': 3}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_find_my_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_find_my_disable failed (Result: $result_value, Expected: "{'integer': 3}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_find_my_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_find_my_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_find_my_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_find_my_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_find_my_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_firewall_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-4
# * CM-7, CM-7(1)
# * SC-7, SC-7(12)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_firewall_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'EnableFirewall = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_firewall_enable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_firewall_enable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_firewall_enable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_firewall_enable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_firewall_enable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_firewall_enable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_firewall_enable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_firewall_enable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_firewall_enable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_firewall_enable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_firewall_stealth_mode_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
# * SC-7, SC-7(16)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_firewall_stealth_mode_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'EnableStealthMode = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_firewall_stealth_mode_enable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_firewall_stealth_mode_enable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_firewall_stealth_mode_enable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_firewall_stealth_mode_enable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_firewall_stealth_mode_enable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_firewall_stealth_mode_enable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_firewall_stealth_mode_enable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_firewall_stealth_mode_enable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_firewall_stealth_mode_enable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_firewall_stealth_mode_enable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_gatekeeper_identified_developers_allowed -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-14
# * CM-5
# * SI-7(1), SI-7(15)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_gatekeeper_identified_developers_allowed ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/sbin/spctl --status --verbose | /usr/bin/grep -c "developer id enabled")
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_gatekeeper_identified_developers_allowed:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_gatekeeper_identified_developers_allowed:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_gatekeeper_identified_developers_allowed passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_gatekeeper_identified_developers_allowed -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_gatekeeper_identified_developers_allowed failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_gatekeeper_identified_developers_allowed -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_gatekeeper_identified_developers_allowed has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_gatekeeper_identified_developers_allowed -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_gatekeeper_identified_developers_allowed does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_gatekeeper_identified_developers_allowed -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_gatekeeper_override_disallow -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-5
# * SI-7(15)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_gatekeeper_override_disallow ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'DisableOverride = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_gatekeeper_override_disallow:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_gatekeeper_override_disallow:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_gatekeeper_override_disallow passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_gatekeeper_override_disallow -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_gatekeeper_override_disallow failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_gatekeeper_override_disallow -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_gatekeeper_override_disallow has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_gatekeeper_override_disallow -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_gatekeeper_override_disallow does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_gatekeeper_override_disallow -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_guest_access_smb_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2, AC-2(9)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_guest_access_smb_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess)
    # expected result {'boolean': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_guest_access_smb_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_guest_access_smb_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) sysprefs_guest_access_smb_disable passed (Result: $result_value, Expected: "{'boolean': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_guest_access_smb_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_guest_access_smb_disable failed (Result: $result_value, Expected: "{'boolean': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_guest_access_smb_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_guest_access_smb_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_guest_access_smb_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_guest_access_smb_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_guest_access_smb_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_guest_account_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2, AC-2(9)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_guest_account_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'DisableGuestAccount = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_guest_account_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_guest_account_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_guest_account_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_guest_account_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_guest_account_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_guest_account_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_guest_account_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_guest_account_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_guest_account_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_guest_account_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_hot_corners_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_hot_corners_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '"wvous-bl-corner" = 0|"wvous-br-corner" = 0|"wvous-tl-corner" = 0|"wvous-tr-corner" = 0')
    # expected result {'integer': 4}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_hot_corners_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_hot_corners_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "4" ]]; then
            echo "$(date -u) sysprefs_hot_corners_disable passed (Result: $result_value, Expected: "{'integer': 4}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_hot_corners_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_hot_corners_disable failed (Result: $result_value, Expected: "{'integer': 4}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_hot_corners_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_hot_corners_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_hot_corners_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_hot_corners_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_hot_corners_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_improve_siri_dictation_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_improve_siri_dictation_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c '"Siri Data Sharing Opt-In Status" = 2;')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_improve_siri_dictation_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_improve_siri_dictation_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_improve_siri_dictation_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_improve_siri_dictation_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_improve_siri_dictation_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_improve_siri_dictation_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_improve_siri_dictation_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_improve_siri_dictation_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_improve_siri_dictation_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_improve_siri_dictation_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_internet_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * AC-4
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_internet_sharing_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'forceInternetSharingOff = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_internet_sharing_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_internet_sharing_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_internet_sharing_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_internet_sharing_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_internet_sharing_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_internet_sharing_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_internet_sharing_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_internet_sharing_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_internet_sharing_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_internet_sharing_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_location_services_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_location_services_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.plist LocationServicesEnabled)
    # expected result {'boolean': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_location_services_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_location_services_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) sysprefs_location_services_disable passed (Result: $result_value, Expected: "{'boolean': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_location_services_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_location_services_disable failed (Result: $result_value, Expected: "{'boolean': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_location_services_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_location_services_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_location_services_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_location_services_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_location_services_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_loginwindow_prompt_username_password_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_loginwindow_prompt_username_password_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SHOWFULLNAME = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_loginwindow_prompt_username_password_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_loginwindow_prompt_username_password_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_loginwindow_prompt_username_password_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_loginwindow_prompt_username_password_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_loginwindow_prompt_username_password_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_loginwindow_prompt_username_password_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_loginwindow_prompt_username_password_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_loginwindow_prompt_username_password_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_loginwindow_prompt_username_password_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_loginwindow_prompt_username_password_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_media_sharing_disabled -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_media_sharing_disabled ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '(homeSharingUIStatus = 0|legacySharingUIStatus = 0|mediaSharingUIStatus = 0)')
    # expected result {'integer': 3}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_media_sharing_disabled:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_media_sharing_disabled:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "3" ]]; then
            echo "$(date -u) sysprefs_media_sharing_disabled passed (Result: $result_value, Expected: "{'integer': 3}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_media_sharing_disabled -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_media_sharing_disabled failed (Result: $result_value, Expected: "{'integer': 3}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_media_sharing_disabled -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_media_sharing_disabled has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_media_sharing_disabled -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_media_sharing_disabled does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_media_sharing_disabled -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_password_hints_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-6
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_password_hints_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'RetriesUntilHint = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_password_hints_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_password_hints_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_password_hints_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_password_hints_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_password_hints_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_password_hints_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_password_hints_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_password_hints_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_password_hints_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_password_hints_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_personalized_advertising_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_personalized_advertising_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowApplePersonalizedAdvertising = 0;')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_personalized_advertising_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_personalized_advertising_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_personalized_advertising_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_personalized_advertising_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_personalized_advertising_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_personalized_advertising_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_personalized_advertising_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_personalized_advertising_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_personalized_advertising_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_personalized_advertising_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_power_nap_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_power_nap_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pmset -g custom | /usr/bin/awk '/powernap/ { sum+=$2 } END {print sum}')
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_power_nap_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_power_nap_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "0" ]]; then
            echo "$(date -u) sysprefs_power_nap_disable passed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_power_nap_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_power_nap_disable failed (Result: $result_value, Expected: "{'integer': 0}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_power_nap_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_power_nap_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_power_nap_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_power_nap_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_power_nap_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_rae_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_rae_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.AEServer" => true')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_rae_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_rae_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_rae_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_rae_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_rae_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_rae_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_rae_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_rae_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_rae_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_rae_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_screen_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_screen_sharing_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.screensharing" => true')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_screen_sharing_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_screen_sharing_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_screen_sharing_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_screen_sharing_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_screen_sharing_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_screen_sharing_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_screen_sharing_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_screen_sharing_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_screen_sharing_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_screen_sharing_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_screensaver_ask_for_password_delay_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_screensaver_ask_for_password_delay_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'askForPasswordDelay = 5')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_screensaver_ask_for_password_delay_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_screensaver_ask_for_password_delay_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_screensaver_ask_for_password_delay_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_screensaver_ask_for_password_delay_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_screensaver_ask_for_password_delay_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_screensaver_ask_for_password_delay_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_screensaver_ask_for_password_delay_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_screensaver_ask_for_password_delay_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_screensaver_ask_for_password_delay_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_screensaver_ask_for_password_delay_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_screensaver_password_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_screensaver_password_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'askForPassword = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_screensaver_password_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_screensaver_password_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_screensaver_password_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_screensaver_password_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_screensaver_password_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_screensaver_password_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_screensaver_password_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_screensaver_password_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_screensaver_password_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_screensaver_password_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_screensaver_timeout_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11
# * IA-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_screensaver_timeout_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/egrep -o -e "idleTime\s=\s([^;]+)" | /usr/bin/awk '{ if ($3 <= 900) {print "Yes"} else {print "No"}}')
    # expected result {'string': 'Yes'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_screensaver_timeout_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_screensaver_timeout_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "Yes" ]]; then
            echo "$(date -u) sysprefs_screensaver_timeout_enforce passed (Result: $result_value, Expected: "{'string': 'Yes'}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_screensaver_timeout_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_screensaver_timeout_enforce failed (Result: $result_value, Expected: "{'string': 'Yes'}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_screensaver_timeout_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_screensaver_timeout_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_screensaver_timeout_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_screensaver_timeout_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_screensaver_timeout_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_siri_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_siri_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c '"Ironwood Allowed" = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_siri_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_siri_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_siri_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_siri_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_siri_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_siri_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_siri_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_siri_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_siri_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_siri_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_smbd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_smbd_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.smbd" => true')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_smbd_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_smbd_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_smbd_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_smbd_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_smbd_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_smbd_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_smbd_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_smbd_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_smbd_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_smbd_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_ssh_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
# * CM-7, CM-7(1)
# * IA-2(8)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_ssh_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.openssh.sshd" => false')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_ssh_enable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_ssh_enable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_ssh_enable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_ssh_enable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_ssh_enable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_ssh_enable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_ssh_enable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_ssh_enable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_ssh_enable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_ssh_enable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_system_wide_preferences_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-6, AC-6(1), AC-6(2)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_system_wide_preferences_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/security authorizationdb read system.preferences 2> /dev/null |  /usr/bin/grep -A 1 "<key>shared</key>" | /usr/bin/grep -c "<false/>")
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_system_wide_preferences_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_system_wide_preferences_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_system_wide_preferences_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_system_wide_preferences_configure -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_system_wide_preferences_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_system_wide_preferences_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_system_wide_preferences_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_system_wide_preferences_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_system_wide_preferences_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_system_wide_preferences_configure -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_time_server_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12(1)
# * SC-45(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_time_server_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/awk -F "= " '/timeServer/{print $2}' | /usr/bin/tr -d ';' | /usr/bin/tr -d '"')
    # expected result {'string': 'time-a.nist.gov,time-b.nist.gov'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_time_server_configure:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_time_server_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "time-a.nist.gov,time-b.nist.gov" ]]; then
            echo "$(date -u) sysprefs_time_server_configure passed (Result: $result_value, Expected: "{'string': 'time-a.nist.gov,time-b.nist.gov'}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_time_server_configure -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_time_server_configure failed (Result: $result_value, Expected: "{'string': 'time-a.nist.gov,time-b.nist.gov'}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_time_server_configure -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_time_server_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_time_server_configure -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_time_server_configure does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_time_server_configure -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_time_server_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12(1)
# * SC-45(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_time_server_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'TMAutomaticTimeOnlyEnabled = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_time_server_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_time_server_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_time_server_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_time_server_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_time_server_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_time_server_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_time_server_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_time_server_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_time_server_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_time_server_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_token_removal_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_token_removal_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'tokenRemovalAction = 1')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_token_removal_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_token_removal_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_token_removal_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_token_removal_enforce -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_token_removal_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_token_removal_enforce -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_token_removal_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_token_removal_enforce -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_token_removal_enforce does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_token_removal_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_touchid_unlock_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_touchid_unlock_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowFingerprintForUnlock = 0')
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print sysprefs_touchid_unlock_disable:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print sysprefs_touchid_unlock_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "1" ]]; then
            echo "$(date -u) sysprefs_touchid_unlock_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_touchid_unlock_disable -dict-add finding -bool NO
        else
            echo "$(date -u) sysprefs_touchid_unlock_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | tee -a "$audit_log"
            defaults write "$audit_plist" sysprefs_touchid_unlock_disable -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) sysprefs_touchid_unlock_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" sysprefs_touchid_unlock_disable -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) sysprefs_touchid_unlock_disable does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_touchid_unlock_disable -dict-add finding -bool NO
fi
    
lastComplianceScan=$(defaults read "$audit_plist" lastComplianceCheck)
echo "Results written to $audit_plist"


}

run_fix(){


# append to existing logfile
echo "$(date -u) Beginning remediation of non-compliant settings" >> "$audit_log"

# run mcxrefresh 
/usr/bin/mcxrefresh -u $CURR_USER_UID


    
#####----- Rule: auth_pam_login_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2(1), IA-2(2), IA-2(8)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print auth_pam_login_smartcard_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print auth_pam_login_smartcard_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)

auth_pam_login_smartcard_enforce_audit_score=$($plb -c "print auth_pam_login_smartcard_enforce:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $auth_pam_login_smartcard_enforce_audit_score == "true" ]]; then
        ask 'auth_pam_login_smartcard_enforce - Run the command(s)-> /bin/cat > /etc/pam.d/login << LOGIN_END
# login: auth account password session
auth        sufficient    pam_smartcard.so
auth        optional      pam_krb5.so use_kcminit
auth        optional      pam_ntlm.so try_first_pass
auth        optional      pam_mount.so try_first_pass
auth        required      pam_opendirectory.so try_first_pass
auth        required      pam_deny.so
account     required      pam_nologin.so
account     required      pam_opendirectory.so
password    required      pam_opendirectory.so
session     required      pam_launchd.so
session     required      pam_uwtmp.so
session     optional      pam_mount.so
LOGIN_END


/bin/chmod 644 /etc/pam.d/login
/usr/sbin/chown root:wheel /etc/pam.d/login ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: auth_pam_login_smartcard_enforce ...' | tee -a "$audit_log"
            /bin/cat > /etc/pam.d/login << LOGIN_END
# login: auth account password session
auth        sufficient    pam_smartcard.so
auth        optional      pam_krb5.so use_kcminit
auth        optional      pam_ntlm.so try_first_pass
auth        optional      pam_mount.so try_first_pass
auth        required      pam_opendirectory.so try_first_pass
auth        required      pam_deny.so
account     required      pam_nologin.so
account     required      pam_opendirectory.so
password    required      pam_opendirectory.so
session     required      pam_launchd.so
session     required      pam_uwtmp.so
session     optional      pam_mount.so
LOGIN_END


/bin/chmod 644 /etc/pam.d/login
/usr/sbin/chown root:wheel /etc/pam.d/login
        fi
    else
        echo 'Settings for: auth_pam_login_smartcard_enforce already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) auth_pam_login_smartcard_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: auth_pam_su_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2(1), IA-2(2), IA-2(8)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print auth_pam_su_smartcard_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print auth_pam_su_smartcard_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)

auth_pam_su_smartcard_enforce_audit_score=$($plb -c "print auth_pam_su_smartcard_enforce:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $auth_pam_su_smartcard_enforce_audit_score == "true" ]]; then
        ask 'auth_pam_su_smartcard_enforce - Run the command(s)-> /bin/cat > /etc/pam.d/su << SU_END
# su: auth account password session
auth        sufficient    pam_smartcard.so
auth        required      pam_rootok.so
auth        required      pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account     required      pam_permit.so
account     required      pam_opendirectory.so no_check_shell
password    required      pam_opendirectory.so
session     required      pam_launchd.so
SU_END

# Fix new file ownership and permissions
/bin/chmod 644 /etc/pam.d/su
/usr/sbin/chown root:wheel /etc/pam.d/su ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: auth_pam_su_smartcard_enforce ...' | tee -a "$audit_log"
            /bin/cat > /etc/pam.d/su << SU_END
# su: auth account password session
auth        sufficient    pam_smartcard.so
auth        required      pam_rootok.so
auth        required      pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account     required      pam_permit.so
account     required      pam_opendirectory.so no_check_shell
password    required      pam_opendirectory.so
session     required      pam_launchd.so
SU_END

# Fix new file ownership and permissions
/bin/chmod 644 /etc/pam.d/su
/usr/sbin/chown root:wheel /etc/pam.d/su
        fi
    else
        echo 'Settings for: auth_pam_su_smartcard_enforce already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) auth_pam_su_smartcard_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: auth_pam_sudo_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2(1), IA-2(2), IA-2(8)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print auth_pam_sudo_smartcard_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print auth_pam_sudo_smartcard_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)

auth_pam_sudo_smartcard_enforce_audit_score=$($plb -c "print auth_pam_sudo_smartcard_enforce:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $auth_pam_sudo_smartcard_enforce_audit_score == "true" ]]; then
        ask 'auth_pam_sudo_smartcard_enforce - Run the command(s)-> /bin/cat > /etc/pam.d/sudo << SUDO_END
# sudo: auth account password session
auth        sufficient    pam_smartcard.so
auth        required      pam_opendirectory.so
auth        required      pam_deny.so
account     required      pam_permit.so
password    required      pam_deny.so
session     required      pam_permit.so
SUDO_END

/bin/chmod 444 /etc/pam.d/sudo
/usr/sbin/chown root:wheel /etc/pam.d/sudo ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: auth_pam_sudo_smartcard_enforce ...' | tee -a "$audit_log"
            /bin/cat > /etc/pam.d/sudo << SUDO_END
# sudo: auth account password session
auth        sufficient    pam_smartcard.so
auth        required      pam_opendirectory.so
auth        required      pam_deny.so
account     required      pam_permit.so
password    required      pam_deny.so
session     required      pam_permit.so
SUDO_END

/bin/chmod 444 /etc/pam.d/sudo
/usr/sbin/chown root:wheel /etc/pam.d/sudo
        fi
    else
        echo 'Settings for: auth_pam_sudo_smartcard_enforce already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) auth_pam_sudo_smartcard_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: auth_ssh_password_authentication_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2, IA-2(1), IA-2(2), IA-2(6), IA-2(8)
# * IA-5(2)
# * MA-4

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print auth_ssh_password_authentication_disable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print auth_ssh_password_authentication_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

auth_ssh_password_authentication_disable_audit_score=$($plb -c "print auth_ssh_password_authentication_disable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $auth_ssh_password_authentication_disable_audit_score == "true" ]]; then
        ask 'auth_ssh_password_authentication_disable - Run the command(s)-> /usr/bin/sed -i.bak_$(date "+%%Y-%%m-%%d_%%H:%%M") "s|#PasswordAuthentication yes|PasswordAuthentication no|; s|#ChallengeResponseAuthentication yes|ChallengeResponseAuthentication no|" /etc/ssh/sshd_config; /bin/launchctl kickstart -k system/com.openssh.sshd ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: auth_ssh_password_authentication_disable ...' | tee -a "$audit_log"
            /usr/bin/sed -i.bak_$(date "+%Y-%m-%d_%H:%M") "s|#PasswordAuthentication yes|PasswordAuthentication no|; s|#ChallengeResponseAuthentication yes|ChallengeResponseAuthentication no|" /etc/ssh/sshd_config; /bin/launchctl kickstart -k system/com.openssh.sshd
        fi
    else
        echo 'Settings for: auth_ssh_password_authentication_disable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) auth_ssh_password_authentication_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_acls_files_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
# * SI-11

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_acls_files_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_acls_files_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_acls_files_configure_audit_score=$($plb -c "print audit_acls_files_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_acls_files_configure_audit_score == "true" ]]; then
        ask 'audit_acls_files_configure - Run the command(s)-> /bin/chmod -RN $(/usr/bin/awk -F: '"'"'/^dir/{print $2}'"'"' /etc/security/audit_control) ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_acls_files_configure ...' | tee -a "$audit_log"
            /bin/chmod -RN $(/usr/bin/awk -F: '/^dir/{print $2}' /etc/security/audit_control)
        fi
    else
        echo 'Settings for: audit_acls_files_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_acls_files_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_acls_folders_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_acls_folders_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_acls_folders_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_acls_folders_configure_audit_score=$($plb -c "print audit_acls_folders_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_acls_folders_configure_audit_score == "true" ]]; then
        ask 'audit_acls_folders_configure - Run the command(s)-> /bin/chmod -N $(/usr/bin/grep '"'"'^dir'"'"' /etc/security/audit_control | /usr/bin/awk -F: '"'"'{print $2}'"'"') ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_acls_folders_configure ...' | tee -a "$audit_log"
            /bin/chmod -N $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
        fi
    else
        echo 'Settings for: audit_acls_folders_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_acls_folders_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_auditd_enabled -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12, AU-12(1), AU-12(3)
# * AU-14(1)
# * AU-3, AU-3(1)
# * AU-8
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_auditd_enabled:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_auditd_enabled:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_auditd_enabled_audit_score=$($plb -c "print audit_auditd_enabled:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_auditd_enabled_audit_score == "true" ]]; then
        ask 'audit_auditd_enabled - Run the command(s)-> /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_auditd_enabled ...' | tee -a "$audit_log"
            /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
        fi
    else
        echo 'Settings for: audit_auditd_enabled already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_auditd_enabled has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_failure_halt -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-5

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_failure_halt:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_failure_halt:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_failure_halt_audit_score=$($plb -c "print audit_failure_halt:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_failure_halt_audit_score == "true" ]]; then
        ask 'audit_failure_halt - Run the command(s)-> /usr/bin/sed -i.bak '"'"'s/^policy.*/policy: ahlt,argv/'"'"' /etc/security/audit_control; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_failure_halt ...' | tee -a "$audit_log"
            /usr/bin/sed -i.bak 's/^policy.*/policy: ahlt,argv/' /etc/security/audit_control; /usr/sbin/audit -s
        fi
    else
        echo 'Settings for: audit_failure_halt already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_failure_halt has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_files_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_files_group_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_files_group_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_files_group_configure_audit_score=$($plb -c "print audit_files_group_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_files_group_configure_audit_score == "true" ]]; then
        ask 'audit_files_group_configure - Run the command(s)-> /usr/bin/chgrp -R wheel $(/usr/bin/grep '"'"'^dir'"'"' /etc/security/audit_control | /usr/bin/awk -F: '"'"'{print $2}'"'"')/* ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_files_group_configure ...' | tee -a "$audit_log"
            /usr/bin/chgrp -R wheel $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')/*
        fi
    else
        echo 'Settings for: audit_files_group_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_files_group_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_files_mode_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_files_mode_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_files_mode_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_files_mode_configure_audit_score=$($plb -c "print audit_files_mode_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_files_mode_configure_audit_score == "true" ]]; then
        ask 'audit_files_mode_configure - Run the command(s)-> /bin/chmod 440 $(/usr/bin/grep '"'"'^dir'"'"' /etc/security/audit_control | /usr/bin/awk -F: '"'"'{print $2}'"'"')/* ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_files_mode_configure ...' | tee -a "$audit_log"
            /bin/chmod 440 $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')/*
        fi
    else
        echo 'Settings for: audit_files_mode_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_files_mode_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_files_owner_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_files_owner_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_files_owner_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_files_owner_configure_audit_score=$($plb -c "print audit_files_owner_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_files_owner_configure_audit_score == "true" ]]; then
        ask 'audit_files_owner_configure - Run the command(s)-> /usr/sbin/chown -R root $(/usr/bin/grep '"'"'^dir'"'"' /etc/security/audit_control | /usr/bin/awk -F: '"'"'{print $2}'"'"')/* ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_files_owner_configure ...' | tee -a "$audit_log"
            /usr/sbin/chown -R root $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')/*
        fi
    else
        echo 'Settings for: audit_files_owner_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_files_owner_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_aa_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_flags_aa_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_flags_aa_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_flags_aa_configure_audit_score=$($plb -c "print audit_flags_aa_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_aa_configure_audit_score == "true" ]]; then
        ask 'audit_flags_aa_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*[^-]aa" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,aa/'"'"' /etc/security/audit_control; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_flags_aa_configure ...' | tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*[^-]aa" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,aa/' /etc/security/audit_control; /usr/sbin/audit -s
        fi
    else
        echo 'Settings for: audit_flags_aa_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_flags_aa_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_ad_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12), AC-2(4)
# * AC-6(9)
# * AU-12
# * AU-2
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_flags_ad_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_flags_ad_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_flags_ad_configure_audit_score=$($plb -c "print audit_flags_ad_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_ad_configure_audit_score == "true" ]]; then
        ask 'audit_flags_ad_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*[^-]ad" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,ad/'"'"' /etc/security/audit_control; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_flags_ad_configure ...' | tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*[^-]ad" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,ad/' /etc/security/audit_control; /usr/sbin/audit -s
        fi
    else
        echo 'Settings for: audit_flags_ad_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_flags_ad_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_ex_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * CM-5(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_flags_ex_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_flags_ex_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_flags_ex_configure_audit_score=$($plb -c "print audit_flags_ex_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_ex_configure_audit_score == "true" ]]; then
        ask 'audit_flags_ex_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*-ex" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,-ex/'"'"' /etc/security/audit_control; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_flags_ex_configure ...' | tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*-ex" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,-ex/' /etc/security/audit_control; /usr/sbin/audit -s
        fi
    else
        echo 'Settings for: audit_flags_ex_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_flags_ex_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_fd_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_flags_fd_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_flags_fd_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_flags_fd_configure_audit_score=$($plb -c "print audit_flags_fd_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_fd_configure_audit_score == "true" ]]; then
        ask 'audit_flags_fd_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*-fd" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,-fd/'"'"' /etc/security/audit_control;/usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_flags_fd_configure ...' | tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*-fd" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,-fd/' /etc/security/audit_control;/usr/sbin/audit -s
        fi
    else
        echo 'Settings for: audit_flags_fd_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_flags_fd_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_fm_failed_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_flags_fm_failed_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_flags_fm_failed_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_flags_fm_failed_configure_audit_score=$($plb -c "print audit_flags_fm_failed_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_fm_failed_configure_audit_score == "true" ]]; then
        ask 'audit_flags_fm_failed_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*-fm" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,-fm/'"'"' /etc/security/audit_control;/usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_flags_fm_failed_configure ...' | tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*-fm" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,-fm/' /etc/security/audit_control;/usr/sbin/audit -s
        fi
    else
        echo 'Settings for: audit_flags_fm_failed_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_flags_fm_failed_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_fr_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_flags_fr_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_flags_fr_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_flags_fr_configure_audit_score=$($plb -c "print audit_flags_fr_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_fr_configure_audit_score == "true" ]]; then
        ask 'audit_flags_fr_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*-fr" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,-fr/'"'"' /etc/security/audit_control;/usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_flags_fr_configure ...' | tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*-fr" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,-fr/' /etc/security/audit_control;/usr/sbin/audit -s
        fi
    else
        echo 'Settings for: audit_flags_fr_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_flags_fr_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_fw_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_flags_fw_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_flags_fw_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_flags_fw_configure_audit_score=$($plb -c "print audit_flags_fw_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_fw_configure_audit_score == "true" ]]; then
        ask 'audit_flags_fw_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*-fw" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,-fw/'"'"' /etc/security/audit_control;/usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_flags_fw_configure ...' | tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*-fw" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,-fw/' /etc/security/audit_control;/usr/sbin/audit -s
        fi
    else
        echo 'Settings for: audit_flags_fw_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_flags_fw_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_lo_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17(1)
# * AC-2(12)
# * AU-12
# * AU-2
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_flags_lo_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_flags_lo_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_flags_lo_configure_audit_score=$($plb -c "print audit_flags_lo_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_lo_configure_audit_score == "true" ]]; then
        ask 'audit_flags_lo_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*[^-]lo" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,lo/'"'"' /etc/security/audit_control; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_flags_lo_configure ...' | tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*[^-]lo" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,lo/' /etc/security/audit_control; /usr/sbin/audit -s
        fi
    else
        echo 'Settings for: audit_flags_lo_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_flags_lo_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_folder_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_folder_group_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_folder_group_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_folder_group_configure_audit_score=$($plb -c "print audit_folder_group_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_folder_group_configure_audit_score == "true" ]]; then
        ask 'audit_folder_group_configure - Run the command(s)-> /usr/bin/chgrp wheel $(/usr/bin/awk -F : '"'"'/^dir/{print $2}'"'"' /etc/security/audit_control) ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_folder_group_configure ...' | tee -a "$audit_log"
            /usr/bin/chgrp wheel $(/usr/bin/awk -F : '/^dir/{print $2}' /etc/security/audit_control)
        fi
    else
        echo 'Settings for: audit_folder_group_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_folder_group_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_folder_owner_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_folder_owner_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_folder_owner_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_folder_owner_configure_audit_score=$($plb -c "print audit_folder_owner_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_folder_owner_configure_audit_score == "true" ]]; then
        ask 'audit_folder_owner_configure - Run the command(s)-> /usr/sbin/chown root $(/usr/bin/awk -F : '"'"'/^dir/{print $2}'"'"' /etc/security/audit_control) ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_folder_owner_configure ...' | tee -a "$audit_log"
            /usr/sbin/chown root $(/usr/bin/awk -F : '/^dir/{print $2}' /etc/security/audit_control)
        fi
    else
        echo 'Settings for: audit_folder_owner_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_folder_owner_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_folders_mode_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_folders_mode_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_folders_mode_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_folders_mode_configure_audit_score=$($plb -c "print audit_folders_mode_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_folders_mode_configure_audit_score == "true" ]]; then
        ask 'audit_folders_mode_configure - Run the command(s)-> /bin/chmod 700 $(/usr/bin/grep '"'"'^dir'"'"' /etc/security/audit_control | /usr/bin/awk -F: '"'"'{print $2}'"'"') ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_folders_mode_configure ...' | tee -a "$audit_log"
            /bin/chmod 700 $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
        fi
    else
        echo 'Settings for: audit_folders_mode_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_folders_mode_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_retention_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-11
# * AU-4

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_retention_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_retention_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_retention_configure_audit_score=$($plb -c "print audit_retention_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_retention_configure_audit_score == "true" ]]; then
        ask 'audit_retention_configure - Run the command(s)-> /usr/bin/sed -i.bak '"'"'s/^expire-after.*/expire-after:7d/'"'"' /etc/security/audit_control; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_retention_configure ...' | tee -a "$audit_log"
            /usr/bin/sed -i.bak 's/^expire-after.*/expire-after:365d/' /etc/security/audit_control; /usr/sbin/audit -s
        fi
    else
        echo 'Settings for: audit_retention_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_retention_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: audit_settings_failure_notify -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-5, AU-5(2)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print audit_settings_failure_notify:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print audit_settings_failure_notify:exempt_reason" "$audit_plist_managed" 2>/dev/null)

audit_settings_failure_notify_audit_score=$($plb -c "print audit_settings_failure_notify:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $audit_settings_failure_notify_audit_score == "true" ]]; then
        ask 'audit_settings_failure_notify - Run the command(s)-> /usr/bin/sed -i.bak '"'"'s/logger -p/logger -s -p/'"'"' /etc/security/audit_warn; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: audit_settings_failure_notify ...' | tee -a "$audit_log"
            /usr/bin/sed -i.bak 's/logger -p/logger -s -p/' /etc/security/audit_warn; /usr/sbin/audit -s
        fi
    else
        echo 'Settings for: audit_settings_failure_notify already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_settings_failure_notify has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_asl_log_files_owner_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-11

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_asl_log_files_owner_group_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_asl_log_files_owner_group_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_asl_log_files_owner_group_configure_audit_score=$($plb -c "print os_asl_log_files_owner_group_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_asl_log_files_owner_group_configure_audit_score == "true" ]]; then
        ask 'os_asl_log_files_owner_group_configure - Run the command(s)-> /usr/sbin/chown root:wheel $(/usr/bin/stat -f '"'"'%%Su:%%Sg:%%N'"'"' $(/usr/bin/grep -e '"'"'^>'"'"' /etc/asl.conf /etc/asl/* | /usr/bin/awk '"'"'{ print $2 }'"'"') 2> /dev/null | /usr/bin/awk '"'"'!/^root:wheel:/{print $1}'"'"' | /usr/bin/awk -F":" '"'"'!/^root:wheel:/{print $3}'"'"') ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_asl_log_files_owner_group_configure ...' | tee -a "$audit_log"
            /usr/sbin/chown root:wheel $(/usr/bin/stat -f '%Su:%Sg:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print $2 }') 2> /dev/null | /usr/bin/awk '!/^root:wheel:/{print $1}' | /usr/bin/awk -F":" '!/^root:wheel:/{print $3}')
        fi
    else
        echo 'Settings for: os_asl_log_files_owner_group_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_asl_log_files_owner_group_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_asl_log_files_permissions_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-11

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_asl_log_files_permissions_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_asl_log_files_permissions_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_asl_log_files_permissions_configure_audit_score=$($plb -c "print os_asl_log_files_permissions_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_asl_log_files_permissions_configure_audit_score == "true" ]]; then
        ask 'os_asl_log_files_permissions_configure - Run the command(s)-> /bin/chmod 640 $(/usr/bin/stat -f '"'"'%%A:%%N'"'"' $(/usr/bin/grep -e '"'"'^>'"'"' /etc/asl.conf /etc/asl/* | /usr/bin/awk '"'"'{ print $2 }'"'"') 2> /dev/null | /usr/bin/awk -F":" '"'"'!/640/{print $2}'"'"') ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_asl_log_files_permissions_configure ...' | tee -a "$audit_log"
            /bin/chmod 640 $(/usr/bin/stat -f '%A:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print $2 }') 2> /dev/null | /usr/bin/awk -F":" '!/640/{print $2}')
        fi
    else
        echo 'Settings for: os_asl_log_files_permissions_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_asl_log_files_permissions_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_authenticated_root_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-3
# * CM-5
# * MA-4(1)
# * SC-34
# * SI-7, SI-7(6)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_authenticated_root_enable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_authenticated_root_enable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_authenticated_root_enable_audit_score=$($plb -c "print os_authenticated_root_enable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_authenticated_root_enable_audit_score == "true" ]]; then
        ask 'os_authenticated_root_enable - Run the command(s)-> /usr/bin/csrutil authenticated-root enable ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_authenticated_root_enable ...' | tee -a "$audit_log"
            /usr/bin/csrutil authenticated-root enable
        fi
    else
        echo 'Settings for: os_authenticated_root_enable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_authenticated_root_enable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_gatekeeper_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-14
# * CM-5
# * SI-3
# * SI-7(1), SI-7(15)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_gatekeeper_enable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_gatekeeper_enable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_gatekeeper_enable_audit_score=$($plb -c "print os_gatekeeper_enable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_gatekeeper_enable_audit_score == "true" ]]; then
        ask 'os_gatekeeper_enable - Run the command(s)-> /usr/sbin/spctl --master-enable ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_gatekeeper_enable ...' | tee -a "$audit_log"
            /usr/sbin/spctl --master-enable
        fi
    else
        echo 'Settings for: os_gatekeeper_enable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_gatekeeper_enable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_home_folders_secure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-6

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_home_folders_secure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_home_folders_secure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_home_folders_secure_audit_score=$($plb -c "print os_home_folders_secure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_home_folders_secure_audit_score == "true" ]]; then
        ask 'os_home_folders_secure - Run the command(s)-> IFS=$'"'"'\n'"'"'
for userDirs in $( /usr/bin/find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d -perm -1 | /usr/bin/grep -v "Shared" | /usr/bin/grep -v "Guest" ); do
  /bin/chmod og-rwx "$userDirs"
done
unset IFS ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_home_folders_secure ...' | tee -a "$audit_log"
            IFS=$'\n'
for userDirs in $( /usr/bin/find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d -perm -1 | /usr/bin/grep -v "Shared" | /usr/bin/grep -v "Guest" ); do
  /bin/chmod og-rwx "$userDirs"
done
unset IFS
        fi
    else
        echo 'Settings for: os_home_folders_secure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_home_folders_secure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_httpd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_httpd_disable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_httpd_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_httpd_disable_audit_score=$($plb -c "print os_httpd_disable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_httpd_disable_audit_score == "true" ]]; then
        ask 'os_httpd_disable - Run the command(s)-> /bin/launchctl disable system/org.apache.httpd ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_httpd_disable ...' | tee -a "$audit_log"
            /bin/launchctl disable system/org.apache.httpd
        fi
    else
        echo 'Settings for: os_httpd_disable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_httpd_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_newsyslog_files_owner_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-11

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_newsyslog_files_owner_group_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_newsyslog_files_owner_group_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_newsyslog_files_owner_group_configure_audit_score=$($plb -c "print os_newsyslog_files_owner_group_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_newsyslog_files_owner_group_configure_audit_score == "true" ]]; then
        ask 'os_newsyslog_files_owner_group_configure - Run the command(s)-> /usr/sbin/chown root:wheel $(/usr/bin/stat -f '"'"'%%Su:%%Sg:%%N'"'"' $(/usr/bin/grep -v '"'"'^#'"'"' /etc/newsyslog.conf | /usr/bin/awk '"'"'{ print $1 }'"'"') 2> /dev/null | /usr/bin/awk -F":" '"'"'!/^root:wheel:/{print $3}'"'"') ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_newsyslog_files_owner_group_configure ...' | tee -a "$audit_log"
            /usr/sbin/chown root:wheel $(/usr/bin/stat -f '%Su:%Sg:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print $1 }') 2> /dev/null | /usr/bin/awk -F":" '!/^root:wheel:/{print $3}')
        fi
    else
        echo 'Settings for: os_newsyslog_files_owner_group_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_newsyslog_files_owner_group_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_newsyslog_files_permissions_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-11

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_newsyslog_files_permissions_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_newsyslog_files_permissions_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_newsyslog_files_permissions_configure_audit_score=$($plb -c "print os_newsyslog_files_permissions_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_newsyslog_files_permissions_configure_audit_score == "true" ]]; then
        ask 'os_newsyslog_files_permissions_configure - Run the command(s)-> /bin/chmod 640 $(/usr/bin/stat -f '"'"'%%A:%%N'"'"' $(/usr/bin/grep -v '"'"'^#'"'"' /etc/newsyslog.conf | /usr/bin/awk '"'"'{ print $1 }'"'"') 2> /dev/null | /usr/bin/awk '"'"'!/640/{print $1}'"'"' | awk -F":" '"'"'!/640/{print $2}'"'"') ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_newsyslog_files_permissions_configure ...' | tee -a "$audit_log"
            /bin/chmod 640 $(/usr/bin/stat -f '%A:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print $1 }') 2> /dev/null | /usr/bin/awk '!/640/{print $1}' | awk -F":" '!/640/{print $2}')
        fi
    else
        echo 'Settings for: os_newsyslog_files_permissions_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_newsyslog_files_permissions_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_nfsd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_nfsd_disable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_nfsd_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_nfsd_disable_audit_score=$($plb -c "print os_nfsd_disable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_nfsd_disable_audit_score == "true" ]]; then
        ask 'os_nfsd_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.nfsd ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_nfsd_disable ...' | tee -a "$audit_log"
            /bin/launchctl disable system/com.apple.nfsd
        fi
    else
        echo 'Settings for: os_nfsd_disable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_nfsd_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_policy_banner_loginwindow_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-8

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_policy_banner_loginwindow_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_policy_banner_loginwindow_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_policy_banner_loginwindow_enforce_audit_score=$($plb -c "print os_policy_banner_loginwindow_enforce:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_policy_banner_loginwindow_enforce_audit_score == "true" ]]; then
        ask 'os_policy_banner_loginwindow_enforce - Run the command(s)-> bannerText="You are accessing a U.S. Government information system, which includes: 1) this computer, 2) this computer network, 3) all Government-furnished computers connected to this network, and 4) all Government-furnished devices and storage media attached to this network or to a computer on this network. You understand and consent to the following: you may access this information system for authorized use only; unauthorized use of the system is prohibited and subject to criminal and civil penalties; you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this information system at any time and for any lawful Government purpose, the Government may monitor, intercept, audit, and search and seize any communication or data transiting or stored on this information system; and any communications or data transiting or stored on this information system may be disclosed or used for any lawful Government purpose. This information system may contain Controlled Unclassified Information (CUI) that is subject to safeguarding or dissemination controls in accordance with law, regulation, or Government-wide policy. Accessing and using this system indicates your understanding of this warning."
/bin/mkdir /Library/Security/PolicyBanner.rtf
/usr/bin/textutil -convert rtf -output /Library/Security/PolicyBanner.rtf/TXT.rtf -stdin <<EOF              
$bannerText
EOF ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_policy_banner_loginwindow_enforce ...' | tee -a "$audit_log"
            bannerText="You are accessing a U.S. Government information system, which includes: 1) this computer, 2) this computer network, 3) all Government-furnished computers connected to this network, and 4) all Government-furnished devices and storage media attached to this network or to a computer on this network. You understand and consent to the following: you may access this information system for authorized use only; unauthorized use of the system is prohibited and subject to criminal and civil penalties; you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this information system at any time and for any lawful Government purpose, the Government may monitor, intercept, audit, and search and seize any communication or data transiting or stored on this information system; and any communications or data transiting or stored on this information system may be disclosed or used for any lawful Government purpose. This information system may contain Controlled Unclassified Information (CUI) that is subject to safeguarding or dissemination controls in accordance with law, regulation, or Government-wide policy. Accessing and using this system indicates your understanding of this warning."
/bin/mkdir /Library/Security/PolicyBanner.rtf
/usr/bin/textutil -convert rtf -output /Library/Security/PolicyBanner.rtf/TXT.rtf -stdin <<EOF              
$bannerText
EOF
        fi
    else
        echo 'Settings for: os_policy_banner_loginwindow_enforce already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_policy_banner_loginwindow_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_root_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2, IA-2(5)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_root_disable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_root_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_root_disable_audit_score=$($plb -c "print os_root_disable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_root_disable_audit_score == "true" ]]; then
        ask 'os_root_disable - Run the command(s)-> /usr/bin/dscl . -create /Users/root UserShell /usr/bin/false ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_root_disable ...' | tee -a "$audit_log"
            /usr/bin/dscl . -create /Users/root UserShell /usr/bin/false
        fi
    else
        echo 'Settings for: os_root_disable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_root_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_sip_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-3
# * AU-9, AU-9(3)
# * CM-5, CM-5(6)
# * SC-4
# * SI-2
# * SI-7

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_sip_enable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_sip_enable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_sip_enable_audit_score=$($plb -c "print os_sip_enable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_sip_enable_audit_score == "true" ]]; then
        ask 'os_sip_enable - Run the command(s)-> /usr/bin/csrutil enable ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_sip_enable ...' | tee -a "$audit_log"
            /usr/bin/csrutil enable
        fi
    else
        echo 'Settings for: os_sip_enable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_sip_enable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_ssh_fips_compliant -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17(2)
# * IA-7
# * SC-13
# * SC-8(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_ssh_fips_compliant:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_ssh_fips_compliant:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_ssh_fips_compliant_audit_score=$($plb -c "print os_ssh_fips_compliant:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_ssh_fips_compliant_audit_score == "true" ]]; then
        ask 'os_ssh_fips_compliant - Run the command(s)-> fips_ssh_config="Host *
Ciphers aes128-gcm@openssh.com
HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
KexAlgorithms ecdh-sha2-nistp256
MACs hmac-sha2-256
PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
CASignatureAlgorithms ecdsa-sha2-nistp256"
/bin/echo "${fips_ssh_config}" > /etc/ssh/ssh_config.d/fips_ssh_config ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_ssh_fips_compliant ...' | tee -a "$audit_log"
            fips_ssh_config="Host *
Ciphers aes128-gcm@openssh.com
HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
KexAlgorithms ecdh-sha2-nistp256
MACs hmac-sha2-256
PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
CASignatureAlgorithms ecdsa-sha2-nistp256"
/bin/echo "${fips_ssh_config}" > /etc/ssh/ssh_config.d/fips_ssh_config
        fi
    else
        echo 'Settings for: os_ssh_fips_compliant already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_ssh_fips_compliant has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_ssh_server_alive_count_max_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SC-10

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_ssh_server_alive_count_max_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_ssh_server_alive_count_max_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_ssh_server_alive_count_max_configure_audit_score=$($plb -c "print os_ssh_server_alive_count_max_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_ssh_server_alive_count_max_configure_audit_score == "true" ]]; then
        ask 'os_ssh_server_alive_count_max_configure - Run the command(s)-> /usr/bin/grep -q '"'"'^ServerAliveCountMax'"'"' /etc/ssh/ssh_config && /usr/bin/sed -i.bak  '"'"'s/.*ServerAliveCountMax.*/ServerAliveCountMax 0/'"'"' /etc/ssh/ssh_config || /bin/echo '"'"'ServerAliveCountMax 0'"'"' >> /etc/ssh/ssh_config ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_ssh_server_alive_count_max_configure ...' | tee -a "$audit_log"
            /usr/bin/grep -q '^ServerAliveCountMax' /etc/ssh/ssh_config && /usr/bin/sed -i.bak  's/.*ServerAliveCountMax.*/ServerAliveCountMax 0/' /etc/ssh/ssh_config || /bin/echo 'ServerAliveCountMax 0' >> /etc/ssh/ssh_config
        fi
    else
        echo 'Settings for: os_ssh_server_alive_count_max_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_ssh_server_alive_count_max_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_ssh_server_alive_interval_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-12
# * SC-10

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_ssh_server_alive_interval_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_ssh_server_alive_interval_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_ssh_server_alive_interval_configure_audit_score=$($plb -c "print os_ssh_server_alive_interval_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_ssh_server_alive_interval_configure_audit_score == "true" ]]; then
        ask 'os_ssh_server_alive_interval_configure - Run the command(s)-> /usr/bin/grep -q '"'"'^ServerAliveInterval'"'"' /etc/ssh/ssh_config && /usr/bin/sed -i.bak  '"'"'s/.*ServerAliveInterval.*/ServerAliveInterval 900/'"'"' /etc/ssh/ssh_config || /bin/echo '"'"'ServerAliveInterval 900'"'"' >> /etc/ssh/ssh_config ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_ssh_server_alive_interval_configure ...' | tee -a "$audit_log"
            /usr/bin/grep -q '^ServerAliveInterval' /etc/ssh/ssh_config && /usr/bin/sed -i.bak  's/.*ServerAliveInterval.*/ServerAliveInterval 900/' /etc/ssh/ssh_config || /bin/echo 'ServerAliveInterval 900' >> /etc/ssh/ssh_config
        fi
    else
        echo 'Settings for: os_ssh_server_alive_interval_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_ssh_server_alive_interval_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_sshd_fips_compliant -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17(2)
# * IA-7
# * SC-13
# * SC-8(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_sshd_fips_compliant:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_sshd_fips_compliant:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_sshd_fips_compliant_audit_score=$($plb -c "print os_sshd_fips_compliant:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_sshd_fips_compliant_audit_score == "true" ]]; then
        ask 'os_sshd_fips_compliant - Run the command(s)-> fips_sshd_config="Ciphers aes128-gcm@openssh.com
HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
KexAlgorithms ecdh-sha2-nistp256
MACs hmac-sha2-256
PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
CASignatureAlgorithms ecdsa-sha2-nistp256"
/bin/echo "${fips_sshd_config}" > /etc/ssh/sshd_config.d/fips_sshd_config ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_sshd_fips_compliant ...' | tee -a "$audit_log"
            fips_sshd_config="Ciphers aes128-gcm@openssh.com
HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
KexAlgorithms ecdh-sha2-nistp256
MACs hmac-sha2-256
PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
CASignatureAlgorithms ecdsa-sha2-nistp256"
/bin/echo "${fips_sshd_config}" > /etc/ssh/sshd_config.d/fips_sshd_config
        fi
    else
        echo 'Settings for: os_sshd_fips_compliant already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_sshd_fips_compliant has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_sudoers_tty_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-5(1)
# * IA-11

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_sudoers_tty_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_sudoers_tty_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_sudoers_tty_configure_audit_score=$($plb -c "print os_sudoers_tty_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_sudoers_tty_configure_audit_score == "true" ]]; then
        ask 'os_sudoers_tty_configure - Run the command(s)-> /bin/cp /etc/sudoers /etc/sudoers.bk; /bin/echo "Defaults tty_tickets" >> /etc/sudoers ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_sudoers_tty_configure ...' | tee -a "$audit_log"
            /bin/cp /etc/sudoers /etc/sudoers.bk; /bin/echo "Defaults tty_tickets" >> /etc/sudoers
        fi
    else
        echo 'Settings for: os_sudoers_tty_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_sudoers_tty_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_tftpd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
# * IA-5(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_tftpd_disable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_tftpd_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_tftpd_disable_audit_score=$($plb -c "print os_tftpd_disable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_tftpd_disable_audit_score == "true" ]]; then
        ask 'os_tftpd_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.tftpd ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_tftpd_disable ...' | tee -a "$audit_log"
            /bin/launchctl disable system/com.apple.tftpd
        fi
    else
        echo 'Settings for: os_tftpd_disable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_tftpd_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_time_server_enabled -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12(1)
# * SC-45(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_time_server_enabled:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_time_server_enabled:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_time_server_enabled_audit_score=$($plb -c "print os_time_server_enabled:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_time_server_enabled_audit_score == "true" ]]; then
        ask 'os_time_server_enabled - Run the command(s)-> /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.timed.plist ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_time_server_enabled ...' | tee -a "$audit_log"
            /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.timed.plist
        fi
    else
        echo 'Settings for: os_time_server_enabled already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_time_server_enabled has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_unlock_active_user_session_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2, IA-2(5)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_unlock_active_user_session_disable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_unlock_active_user_session_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_unlock_active_user_session_disable_audit_score=$($plb -c "print os_unlock_active_user_session_disable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_unlock_active_user_session_disable_audit_score == "true" ]]; then
        ask 'os_unlock_active_user_session_disable - Run the command(s)-> /usr/bin/security authorizationdb write system.login.screensaver "use-login-window-ui" ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_unlock_active_user_session_disable ...' | tee -a "$audit_log"
            /usr/bin/security authorizationdb write system.login.screensaver "use-login-window-ui"
        fi
    else
        echo 'Settings for: os_unlock_active_user_session_disable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_unlock_active_user_session_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: os_uucp_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print os_uucp_disable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print os_uucp_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

os_uucp_disable_audit_score=$($plb -c "print os_uucp_disable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $os_uucp_disable_audit_score == "true" ]]; then
        ask 'os_uucp_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.uucp ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: os_uucp_disable ...' | tee -a "$audit_log"
            /bin/launchctl disable system/com.apple.uucp
        fi
    else
        echo 'Settings for: os_uucp_disable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_uucp_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: pwpolicy_account_inactivity_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(3)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print pwpolicy_account_inactivity_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print pwpolicy_account_inactivity_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)

pwpolicy_account_inactivity_enforce_audit_score=$($plb -c "print pwpolicy_account_inactivity_enforce:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $pwpolicy_account_inactivity_enforce_audit_score == "true" ]]; then
        ask 'pwpolicy_account_inactivity_enforce - Run the command(s)-> /usr/bin/pwpolicy setaccountpolicies $pwpolicy_file ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: pwpolicy_account_inactivity_enforce ...' | tee -a "$audit_log"
            /usr/bin/pwpolicy setaccountpolicies $pwpolicy_file
        fi
    else
        echo 'Settings for: pwpolicy_account_inactivity_enforce already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) pwpolicy_account_inactivity_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: pwpolicy_lower_case_character_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print pwpolicy_lower_case_character_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print pwpolicy_lower_case_character_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)

pwpolicy_lower_case_character_enforce_audit_score=$($plb -c "print pwpolicy_lower_case_character_enforce:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $pwpolicy_lower_case_character_enforce_audit_score == "true" ]]; then
        ask 'pwpolicy_lower_case_character_enforce - Run the command(s)-> /usr/bin/pwpolicy setaccountpolicies $pwpolicy_file ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: pwpolicy_lower_case_character_enforce ...' | tee -a "$audit_log"
            /usr/bin/pwpolicy setaccountpolicies $pwpolicy_file
        fi
    else
        echo 'Settings for: pwpolicy_lower_case_character_enforce already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) pwpolicy_lower_case_character_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: pwpolicy_minimum_lifetime_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print pwpolicy_minimum_lifetime_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print pwpolicy_minimum_lifetime_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)

pwpolicy_minimum_lifetime_enforce_audit_score=$($plb -c "print pwpolicy_minimum_lifetime_enforce:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $pwpolicy_minimum_lifetime_enforce_audit_score == "true" ]]; then
        ask 'pwpolicy_minimum_lifetime_enforce - Run the command(s)-> /usr/bin/pwpolicy setaccountpolicies $pwpolicy_file ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: pwpolicy_minimum_lifetime_enforce ...' | tee -a "$audit_log"
            /usr/bin/pwpolicy setaccountpolicies $pwpolicy_file
        fi
    else
        echo 'Settings for: pwpolicy_minimum_lifetime_enforce already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) pwpolicy_minimum_lifetime_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: pwpolicy_upper_case_character_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print pwpolicy_upper_case_character_enforce:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print pwpolicy_upper_case_character_enforce:exempt_reason" "$audit_plist_managed" 2>/dev/null)

pwpolicy_upper_case_character_enforce_audit_score=$($plb -c "print pwpolicy_upper_case_character_enforce:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $pwpolicy_upper_case_character_enforce_audit_score == "true" ]]; then
        ask 'pwpolicy_upper_case_character_enforce - Run the command(s)-> /usr/bin/pwpolicy setaccountpolicies $pwpolicy_file ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: pwpolicy_upper_case_character_enforce ...' | tee -a "$audit_log"
            /usr/bin/pwpolicy setaccountpolicies $pwpolicy_file
        fi
    else
        echo 'Settings for: pwpolicy_upper_case_character_enforce already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) pwpolicy_upper_case_character_enforce has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_bluetooth_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-18(4)
# * AC-3
# * CM-7, CM-7(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print sysprefs_bluetooth_sharing_disable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print sysprefs_bluetooth_sharing_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

sysprefs_bluetooth_sharing_disable_audit_score=$($plb -c "print sysprefs_bluetooth_sharing_disable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_bluetooth_sharing_disable_audit_score == "true" ]]; then
        ask 'sysprefs_bluetooth_sharing_disable - Run the command(s)-> /usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: sysprefs_bluetooth_sharing_disable ...' | tee -a "$audit_log"
            /usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false
        fi
    else
        echo 'Settings for: sysprefs_bluetooth_sharing_disable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) sysprefs_bluetooth_sharing_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_gatekeeper_identified_developers_allowed -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-14
# * CM-5
# * SI-7(1), SI-7(15)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print sysprefs_gatekeeper_identified_developers_allowed:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print sysprefs_gatekeeper_identified_developers_allowed:exempt_reason" "$audit_plist_managed" 2>/dev/null)

sysprefs_gatekeeper_identified_developers_allowed_audit_score=$($plb -c "print sysprefs_gatekeeper_identified_developers_allowed:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_gatekeeper_identified_developers_allowed_audit_score == "true" ]]; then
        ask 'sysprefs_gatekeeper_identified_developers_allowed - Run the command(s)-> /usr/sbin/spctl --master-enable; /usr/sbin/spctl --enable ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: sysprefs_gatekeeper_identified_developers_allowed ...' | tee -a "$audit_log"
            /usr/sbin/spctl --master-enable; /usr/sbin/spctl --enable
        fi
    else
        echo 'Settings for: sysprefs_gatekeeper_identified_developers_allowed already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) sysprefs_gatekeeper_identified_developers_allowed has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_guest_access_smb_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2, AC-2(9)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print sysprefs_guest_access_smb_disable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print sysprefs_guest_access_smb_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

sysprefs_guest_access_smb_disable_audit_score=$($plb -c "print sysprefs_guest_access_smb_disable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_guest_access_smb_disable_audit_score == "true" ]]; then
        ask 'sysprefs_guest_access_smb_disable - Run the command(s)-> /usr/sbin/sysadminctl -smbGuestAccess off ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: sysprefs_guest_access_smb_disable ...' | tee -a "$audit_log"
            /usr/sbin/sysadminctl -smbGuestAccess off
        fi
    else
        echo 'Settings for: sysprefs_guest_access_smb_disable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) sysprefs_guest_access_smb_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_location_services_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
# * SC-7(10)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print sysprefs_location_services_disable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print sysprefs_location_services_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

sysprefs_location_services_disable_audit_score=$($plb -c "print sysprefs_location_services_disable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_location_services_disable_audit_score == "true" ]]; then
        ask 'sysprefs_location_services_disable - Run the command(s)-> /usr/bin/defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -bool false; /bin/launchctl kickstart -k system/com.apple.locationd ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: sysprefs_location_services_disable ...' | tee -a "$audit_log"
            /usr/bin/defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -bool false; /bin/launchctl kickstart -k system/com.apple.locationd
        fi
    else
        echo 'Settings for: sysprefs_location_services_disable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) sysprefs_location_services_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_power_nap_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print sysprefs_power_nap_disable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print sysprefs_power_nap_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

sysprefs_power_nap_disable_audit_score=$($plb -c "print sysprefs_power_nap_disable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_power_nap_disable_audit_score == "true" ]]; then
        ask 'sysprefs_power_nap_disable - Run the command(s)-> /usr/bin/pmset -a powernap 0 ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: sysprefs_power_nap_disable ...' | tee -a "$audit_log"
            /usr/bin/pmset -a powernap 0
        fi
    else
        echo 'Settings for: sysprefs_power_nap_disable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) sysprefs_power_nap_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_rae_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print sysprefs_rae_disable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print sysprefs_rae_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

sysprefs_rae_disable_audit_score=$($plb -c "print sysprefs_rae_disable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_rae_disable_audit_score == "true" ]]; then
        ask 'sysprefs_rae_disable - Run the command(s)-> /usr/sbin/systemsetup -setremoteappleevents off
/bin/launchctl disable system/com.apple.AEServer ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: sysprefs_rae_disable ...' | tee -a "$audit_log"
            /usr/sbin/systemsetup -setremoteappleevents off
/bin/launchctl disable system/com.apple.AEServer
        fi
    else
        echo 'Settings for: sysprefs_rae_disable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) sysprefs_rae_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_screen_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print sysprefs_screen_sharing_disable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print sysprefs_screen_sharing_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

sysprefs_screen_sharing_disable_audit_score=$($plb -c "print sysprefs_screen_sharing_disable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_screen_sharing_disable_audit_score == "true" ]]; then
        ask 'sysprefs_screen_sharing_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.screensharing ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: sysprefs_screen_sharing_disable ...' | tee -a "$audit_log"
            /bin/launchctl disable system/com.apple.screensharing
        fi
    else
        echo 'Settings for: sysprefs_screen_sharing_disable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) sysprefs_screen_sharing_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_smbd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print sysprefs_smbd_disable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print sysprefs_smbd_disable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

sysprefs_smbd_disable_audit_score=$($plb -c "print sysprefs_smbd_disable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_smbd_disable_audit_score == "true" ]]; then
        ask 'sysprefs_smbd_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.smbd ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: sysprefs_smbd_disable ...' | tee -a "$audit_log"
            /bin/launchctl disable system/com.apple.smbd
        fi
    else
        echo 'Settings for: sysprefs_smbd_disable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) sysprefs_smbd_disable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_ssh_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
# * CM-7, CM-7(1)
# * IA-2(8)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print sysprefs_ssh_enable:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print sysprefs_ssh_enable:exempt_reason" "$audit_plist_managed" 2>/dev/null)

sysprefs_ssh_enable_audit_score=$($plb -c "print sysprefs_ssh_enable:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_ssh_enable_audit_score == "true" ]]; then
        ask 'sysprefs_ssh_enable - Run the command(s)-> /bin/launchctl enable system/com.openssh.sshd ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: sysprefs_ssh_enable ...' | tee -a "$audit_log"
            /bin/launchctl enable system/com.openssh.sshd
        fi
    else
        echo 'Settings for: sysprefs_ssh_enable already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) sysprefs_ssh_enable has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_system_wide_preferences_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-6, AC-6(1), AC-6(2)

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print sysprefs_system_wide_preferences_configure:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print sysprefs_system_wide_preferences_configure:exempt_reason" "$audit_plist_managed" 2>/dev/null)

sysprefs_system_wide_preferences_configure_audit_score=$($plb -c "print sysprefs_system_wide_preferences_configure:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_system_wide_preferences_configure_audit_score == "true" ]]; then
        ask 'sysprefs_system_wide_preferences_configure - Run the command(s)-> /usr/bin/security authorizationdb read system.preferences > /tmp/system.preferences.plist
/usr/libexec/PlistBuddy -c "Set :shared false" /tmp/system.preferences.plist
/usr/bin/security authorizationdb write system.preferences < /tmp/system.preferences.plist ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: sysprefs_system_wide_preferences_configure ...' | tee -a "$audit_log"
            /usr/bin/security authorizationdb read system.preferences > /tmp/system.preferences.plist
/usr/libexec/PlistBuddy -c "Set :shared false" /tmp/system.preferences.plist
/usr/bin/security authorizationdb write system.preferences < /tmp/system.preferences.plist
        fi
    else
        echo 'Settings for: sysprefs_system_wide_preferences_configure already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) sysprefs_system_wide_preferences_configure has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    
echo "$(date -u) Remediation complete" >> "$audit_log"

}

echo "Running Scan"
run_scan
echo "Scan Finished"

echo "Running Fix"
run_fix
echo "Fix Finished"

echo "Running Scan"
run_scan
echo "Scan Finished"

echo "Generating Stats"
generate_stats
echo "Stats Generated"
  
