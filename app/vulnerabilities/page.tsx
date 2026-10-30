import VulnerabilitiesClient, { type CisaVulnerability } from "@/components/VulnerabilitiesClient";

export const revalidate = 3600;

interface CisaKevFeed {
  title?: string;
  catalogVersion?: string;
  dateReleased?: string;
  count?: number;
  vulnerabilities: CisaVulnerability[];
}

const CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

async function fetchLatestKev(): Promise<{
  items: CisaVulnerability[];
  catalogVersion?: string;
  dateReleased?: string;
  totalCount?: number;
  error?: string;
}> {
  try {
    const res = await fetch(CISA_KEV_URL, {
      next: { revalidate: 3600 },
      headers: { Accept: "application/json" },
    });
    if (!res.ok) {
      return { items: [], error: `CISA KEV feed returned HTTP ${res.status}.` };
    }
    const data = (await res.json()) as CisaKevFeed;
    const list = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
    const sorted = [...list].sort((a, b) => (b.dateAdded ?? "").localeCompare(a.dateAdded ?? ""));
    return {
      items: sorted.slice(0, 10),
      catalogVersion: data.catalogVersion,
      dateReleased: data.dateReleased,
      totalCount: data.count ?? list.length,
    };
  } catch {
    return {
      items: [],
      error: "ไม่สามารถดึงข้อมูลจาก CISA KEV API ได้ในขณะนี้ กรุณาตรวจสอบการเชื่อมต่ออินเทอร์เน็ตแล้วลองใหม่อีกครั้ง",
    };
  }
}

export default async function VulnerabilitiesPage() {
  const data = await fetchLatestKev();
  return <VulnerabilitiesClient {...data} />;
}
