#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>

using namespace std;

int calculate_risk(const string& event)
{
    int score = 0;

    // Basic zero-trust behavioral rules
    if (event.find("COMM=sudo") != string::npos)
        score += 30;

    if (event.find("COMM=sh") != string::npos)
        score += 20;

    if (event.find("COMM=bash") != string::npos)
        score += 10;

    return score;
}

string get_level(int score)
{
    if (score >= 50)
        return "HIGH";

    if (score >= 20)
        return "MEDIUM";

    return "LOW";
}

int main()
{
    const char* device = "/dev/process_auditor";

    cout << "========================================\n";
    cout << " Process Syscall Auditor\n";
    cout << " Zero-Trust Behavioral Agent\n";
    cout << "========================================\n";

    ifstream input(device);

    if (!input.is_open())
    {
        cerr << "ERROR: Cannot open " << device << endl;
        cerr << "Run the agent with sudo.\n";
        return 1;
    }

    string event;

    getline(input, event);

    if (event.empty())
    {
        cout << "No event available.\n";
        return 0;
    }

    int risk = calculate_risk(event);
    string level = get_level(risk);

    cout << "\n[EVENT]\n";
    cout << event << endl;

    cout << "\n[BEHAVIOR ANALYSIS]\n";
    cout << "Risk Score : " << risk << endl;
    cout << "Risk Level : " << level << endl;

    if (level == "HIGH")
    {
        cout << "Decision   : ALERT\n";
    }
    else if (level == "MEDIUM")
    {
        cout << "Decision   : MONITOR\n";
    }
    else
    {
        cout << "Decision   : ALLOW\n";
    }

    // Save the event to an audit log
    ofstream log("audit.log", ios::app);

    if (log.is_open())
    {
        log << event
            << " | RISK=" << risk
            << " | LEVEL=" << level
            << "\n";

        log.close();
    }

    cout << "\nAudit record saved to audit.log\n";

    return 0;
}
