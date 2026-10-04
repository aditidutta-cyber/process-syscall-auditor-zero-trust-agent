#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>

using namespace std;


struct AnalysisResult {
    int risk;
    string profile;
    string level;
    string decision;
};

AnalysisResult analyze_event(const string& event)
{
    AnalysisResult result{0, "NORMAL_EXECUTION", "LOW", "ALLOW"};

    if (event.find("UID=0") != string::npos) {
        result.risk += 20;
        result.profile = "PRIVILEGED_EXECUTION";
    }


    if (event.find("COMM=bash") != string::npos ||
        event.find("COMM=sh") != string::npos ||
        event.find("COMM=zsh") != string::npos) {

        result.risk += 20;
        result.profile = "SHELL_EXECUTION";
    }


    if (event.find("COMM=nc") != string::npos ||
        event.find("COMM=ncat") != string::npos ||
        event.find("COMM=nmap") != string::npos ||
        event.find("COMM=netcat") != string::npos) {

        result.risk += 40;
        result.profile = "SUSPICIOUS_UTILITY";
    }


    if (result.risk >= 50) {
        result.level = "HIGH";
        result.decision = "ALERT";
    }
    else if (result.risk >= 20) {
        result.level = "MEDIUM";
        result.decision = "MONITOR";
    }
    else {
        result.level = "LOW";
        result.decision = "ALLOW";
    }

    return result;
}

int main()
{
    const char* device = "/dev/process_auditor";

    cout << "========================================\n";
    cout << " Process Syscall Auditor\n";
    cout << " Zero-Trust Behavioral Agent\n";
    cout << "========================================\n";

    ifstream input(device);

    if (!input.is_open()) {
        cerr << "ERROR: Cannot open " << device << "\n";
        cerr << "Run the agent with sudo.\n";
        return 1;
    }

    string event;

    getline(input, event);

    if (event.empty()) {
        cout << "No syscall execution event available.\n";
        return 0;
    }

    AnalysisResult result = analyze_event(event);

    cout << "\n[SYSCALL AUDIT]\n";
    cout << "System Call : execve\n";
    cout << "Event       : " << event << "\n";

    cout << "\n[SECURITY PROFILE]\n";
    cout << "Profile     : " << result.profile << "\n";

    cout << "\n[BEHAVIOR ANALYSIS]\n";
    cout << "Risk Score  : " << result.risk << "\n";
    cout << "Risk Level  : " << result.level << "\n";
    cout << "Decision    : " << result.decision << "\n";

    ofstream log("audit.log", ios::app);

    if (log.is_open()) {
        log << "SYSCALL=execve"
            << " | " << event
            << " | PROFILE=" << result.profile
            << " | RISK=" << result.risk
            << " | LEVEL=" << result.level
            << " | DECISION=" << result.decision
            << "\n";

        log.close();
    }

    cout << "\nAudit record saved to audit.log\n";

    return 0;
}
