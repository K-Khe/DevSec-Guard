import { NextResponse } from "next/server";
import type { CisaVulnerability } from "@/components/VulnerabilitiesClient";

export const revalidate = 3600;

interface CisaKevFeed {
  title?: string;
  catalogVersion?: string;
  dateReleased?: string;
  count?: number;
  vulnerabilities: CisaVulnerability[];
}

const CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const FALLBACK_ITEMS: CisaVulnerability[] = [
  {
    cveID: "CVE-2024-3400",
    vendorProject: "Palo Alto Networks",
    product: "PAN-OS",
    vulnerabilityName: "Palo Alto Networks PAN-OS Command Injection Vulnerability",
    dateAdded: "2024-04-12",
    shortDescription:
      "Palo Alto Networks PAN-OS contains a command injection vulnerability in the GlobalProtect feature that allows an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.",
    requiredAction:
      "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
    dueDate: "2024-04-19",
    knownRansomwareCampaignUse: "Known",
  },
  {
    cveID: "CVE-2024-4577",
    vendorProject: "PHP",
    product: "PHP CGI",
    vulnerabilityName: "PHP CGI Argument Injection Vulnerability",
    dateAdded: "2024-06-12",
    shortDescription:
      "PHP contains an argument injection vulnerability when running in CGI mode that allows remote code execution.",
    requiredAction:
      "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
    dueDate: "2024-07-03",
    knownRansomwareCampaignUse: "Known",
  },
  {
    cveID: "CVE-2024-21762",
    vendorProject: "Fortinet",
    product: "FortiOS",
    vulnerabilityName: "Fortinet FortiOS Out-of-Bounds Write Vulnerability",
    dateAdded: "2024-02-09",
    shortDescription:
      "Fortinet FortiOS contains an out-of-bounds write vulnerability in the SSL VPN daemon that allows an unauthenticated remote attacker to execute arbitrary code or commands.",
    requiredAction:
      "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
    dueDate: "2024-02-16",
    knownRansomwareCampaignUse: "Known",
  },
  {
    cveID: "CVE-2024-3094",
    vendorProject: "Tukaani Project",
    product: "XZ Utils",
    vulnerabilityName: "XZ Utils Malicious Code Injection Vulnerability",
    dateAdded: "2024-04-01",
    shortDescription:
      "XZ Utils contains malicious code that allows unauthorized remote access or authentication bypass via sshd.",
    requiredAction:
      "Apply updates per vendor instructions.",
    dueDate: "2024-04-22",
    knownRansomwareCampaignUse: "Unknown",
  },
  {
    cveID: "CVE-2024-1709",
    vendorProject: "ConnectWise",
    product: "ScreenConnect",
    vulnerabilityName: "ConnectWise ScreenConnect Authentication Bypass Vulnerability",
    dateAdded: "2024-02-22",
    shortDescription:
      "ConnectWise ScreenConnect contains an authentication bypass vulnerability that allows an attacker with network access to the management interface to create a new administrator account.",
    requiredAction:
      "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
    dueDate: "2024-02-29",
    knownRansomwareCampaignUse: "Known",
  },
];

export async function GET() {
  try {
    const res = await fetch(CISA_KEV_URL, {
      next: { revalidate: 3600 },
      headers: { Accept: "application/json" },
    });
    if (!res.ok) {
      return NextResponse.json({
        items: FALLBACK_ITEMS,
        catalogVersion: "Offline Fallback",
        totalCount: FALLBACK_ITEMS.length,
      });
    }
    const data = (await res.json()) as CisaKevFeed;
    const list = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
    const sorted = [...list].sort((a, b) => (b.dateAdded ?? "").localeCompare(a.dateAdded ?? ""));
    return NextResponse.json({
      items: sorted.length > 0 ? sorted.slice(0, 10) : FALLBACK_ITEMS,
      catalogVersion: data.catalogVersion,
      dateReleased: data.dateReleased,
      totalCount: data.count ?? list.length,
    });
  } catch {
    return NextResponse.json({
      items: FALLBACK_ITEMS,
      catalogVersion: "Offline Fallback",
      totalCount: FALLBACK_ITEMS.length,
    });
  }
}

