import type { AnalysisResult, ScanResult } from "./types";

/**
 * 100% Local Offline Remediation Engine.
 * Generates Thai security summaries, actionable findings, and stack-tailored
 * configuration snippets deterministically on the server without sending any
 * data or scan telemetry to external AI providers.
 */
export function buildLocalAnalysis(scan: ScanResult): AnalysisResult {
  const stackLower = (scan.detectedStack ?? []).map((s) => s.toLowerCase());
  const isNextOrVercel = stackLower.includes("next.js") || stackLower.includes("vercel");
  const isApache = stackLower.includes("apache");
  const isCloudflareOrNetlify = stackLower.includes("cloudflare") || stackLower.includes("netlify");
  const isPhpOrWp =
    stackLower.includes("php") ||
    stackLower.includes("wordpress") ||
    scan.htmlFindings.some((f) => f.key === "wordpress-surface" || f.key === "php-version-exposure");

  const missingHeaders = scan.headers.items.filter((h) => h.state === "missing").map((h) => h.label);
  const weakHeaders = scan.headers.items.filter((h) => h.state === "weak").map((h) => h.label);
  const exposedLeaks = scan.leaks.filter((l) => l.state === "exposed").map((l) => l.path);
  const weakCookies = scan.cookies.filter((c) => c.state === "weak");

  // 1. Build Thai Summary
  const summaryParts: string[] = [];
  if (exposedLeaks.length > 0) {
    summaryParts.push(
      `ตรวจพบความเสี่ยงวิกฤตจากการเปิดเผยไฟล์สำคัญสู่สาธารณะ (${exposedLeaks.join(", ")}) ซึ่งต้องปิดกั้นการเข้าถึงและหมุนเวียน (Rotate) คีย์ความลับทันที`,
    );
  } else {
    summaryParts.push("ไม่พบการรั่วไหลของไฟล์ .env หรือ .git/HEAD สู่สาธารณะ");
  }

  if (missingHeaders.length === 0 && weakHeaders.length === 0) {
    summaryParts.push("ตั้งค่า HTTP Security Headers ครบถ้วนตามมาตรฐานสากล (OWASP / MDN Observatory)");
  } else {
    const issues: string[] = [];
    if (missingHeaders.length > 0) issues.push(`ขาด Header สำคัญ (${missingHeaders.slice(0, 4).join(", ")})`);
    if (weakHeaders.length > 0) issues.push(`มีการตั้งค่าที่ยังไม่รัดกุม (${weakHeaders.join(", ")})`);
    summaryParts.push(`แต่${issues.join(" และ ")} ซึ่งควรเสริมความแข็งแกร่งเพื่อป้องกัน XSS, Clickjacking และการโจมตีลดระดับโปรโตคอล`);
  }

  if (isPhpOrWp) {
    summaryParts.push(
      "นอกจากนี้ระบบตรวจพบร่องรอย PHP / WordPress จึงแนะนำให้ปิดการเปิดเผยเลขเวอร์ชัน (expose_php = Off) และจำกัดช่องทาง xmlrpc.php เพื่อลดพื้นที่เสี่ยงต่อช่องโหว่ระดับหน่วยความจำ",
    );
  }

  const summary = summaryParts.join(" ");

  let laymanSummary: string;
  if (exposedLeaks.length > 0) {
    laymanSummary =
      "เหมือนบ้านที่เผลอวางสมุดจดรหัสตู้เซฟและกุญแจสำรองทิ้งไว้หน้าประตูรั้วให้ใครเดินผ่านไปมาหยิบดูก็ได้ จำเป็นต้องรีบเก็บกุญแจเข้าที่และเปลี่ยนแม่กุญแจใหม่ทั้งหมดทันที";
  } else if (scan.score >= 85) {
    laymanSummary =
      "เหมือนอาคารสมัยใหม่ที่ล็อกประตูนิรภัยทุกชั้น มีรปภ. คอยตรวจรายชื่อแขกก่อนเข้างาน และเก็บตู้เซฟความลับไว้อย่างมิดชิด การป้องกันพื้นฐานแข็งแกร่งและปลอดภัยต่อผู้ใช้งานมากครับ";
  } else if (scan.score >= 60) {
    laymanSummary =
      "เหมือนบ้านที่ล็อกประตูใหญ่หน้าบ้านแน่นหนาและเก็บของมีค่าไว้ในเซฟเรียบร้อย แต่ยังลืมปิดหน้าต่างข้างบ้านบางบาน เพียงแค่ติดตั้งกลอนหน้าต่างเพิ่มตามโค้ดแนะนำก็จะปลอดภัยครบสมบูรณ์ครับ";
  } else {
    laymanSummary =
      "เหมือนร้านค้าที่เก็บตู้เซฟหลังร้านไว้มิดชิด แต่กลับไม่ได้ติดกล้องวงจรปิดหรือยามรักษาความปลอดภัยหน้าร้านเลย ทำให้มิจฉาชีพอาจแอบสวมรอยหรือทำป้ายปลอมมาหลอกลูกค้าหน้าร้านได้ง่าย";
  }

  // 2. Build Actionable Thai Findings (2 to 5 bullets)
  const findings: string[] = [];

  if (exposedLeaks.length > 0) {
    findings.push(
      `พบไฟล์ความลับเปิดเผยสู่สาธารณะ (${exposedLeaks.join(", ")}) — บล็อกเส้นทางดังกล่าวใน Web Server และเปลี่ยน API Keys/Secrets ทั้งหมดทันที`,
    );
  }

  if (missingHeaders.length > 0) {
    findings.push(
      `ขาด HTTP Security Headers มาตรฐาน: ${missingHeaders.join(", ")} ทำให้เบราว์เซอร์ขาดเกราะป้องกัน XSS, Clickjacking และ MIME Sniffing`,
    );
  }

  if (weakHeaders.length > 0) {
    findings.push(
      `Security Headers บางตัวตั้งค่าไม่รัดกุม (${weakHeaders.join(", ")}) เช่น มี 'unsafe-inline'/'unsafe-eval' ใน script-src หรือ max-age ของ HSTS ต่ำกว่า 6 เดือน`,
    );
  }

  if (scan.headers.exposures && scan.headers.exposures.length > 0) {
    const expList = scan.headers.exposures.map((e) => `${e.header}: ${e.value}`).join(", ");
    findings.push(
      `เซิร์ฟเวอร์เปิดเผยข้อมูลเทคโนโลยี/เลขเวอร์ชันผ่าน Header (${expList}) ซึ่งช่วยให้บอทสแกนหาช่องโหว่เฉพาะเวอร์ชันได้ง่ายขึ้น`,
    );
  }

  const htmlFindingThMap: Record<string, string> = {
    "mixed-content":
      "พบการโหลดทรัพยากรผ่าน HTTP บนหน้า HTTPS (Mixed Content) ควรเปลี่ยนลิงก์รูปภาพและสคริปต์ทั้งหมดให้เป็น https://",
    "insecure-form":
      "พบแบบฟอร์ม (<form>) ส่งข้อมูลผ่าน http:// ที่ไม่ได้เข้ารหัส เสี่ยงต่อการถูกดักฟังข้อมูลระหว่างทาง",
    "source-map":
      "พบไฟล์ Source Map (.map) เปิดเผยในหน้าเว็บ แนะนำให้ปิดการสร้าง Source Map บนระบบ Production",
    "possible-secret":
      "พบรูปแบบข้อความคล้ายคีย์ลับ (API Key / Secret / Token) ในซอร์สโค้ดหน้าเว็บ ควรตรวจสอบและย้ายไปเก็บในตัวแปรสภาพแวดล้อมฝั่งเซิร์ฟเวอร์",
    "unsafe-blank-link":
      "พบลิงก์เปิดแท็บใหม่ (target=\"_blank\") ที่ไม่ได้ระบุ rel=\"noopener\" ควรเพิ่ม rel=\"noopener noreferrer\"",
    "missing-sri":
      "พบสคริปต์ภายนอก (CDN) ที่ไม่ได้ระบุค่า Subresource Integrity (integrity=\"sha384-...\")",
    "wordpress-surface":
      "ตรวจพบร่องรอยระบบ WordPress ควรอัปเดตปลั๊กอินให้เป็นปัจจุบันและบล็อก /xmlrpc.php หากไม่ได้ใช้งาน",
    "php-version-exposure":
      "ตรวจพบการเปิดเผยเลขเวอร์ชัน PHP ควรตั้งค่า expose_php = Off ใน php.ini เพื่อซ่อนเลขเวอร์ชัน",
  };

  for (const hf of scan.htmlFindings) {
    const mapped = htmlFindingThMap[hf.key];
    if (mapped) {
      findings.push(mapped);
    } else if (hf.severity === "high" || hf.severity === "medium") {
      findings.push(`ตรวจพบความเสี่ยงในโครงสร้าง HTML (${hf.title})`);
    }
  }

  if (weakCookies.length > 0) {
    findings.push(
      `พบคุกกี้ ${weakCookies.length} รายการ ที่ยังไม่ได้ตั้งค่า Secure, HttpOnly หรือ SameSite ให้ครบถ้วน`,
    );
  }

  if (findings.length === 0) {
    findings.push("ผ่านเกณฑ์ HTTP Security Headers พื้นฐานและไม่พบไฟล์ .env/.git รั่วไหลสู่สาธารณะ");
    findings.push("แนะนำให้พิจารณาเพิ่ม Cross-Origin Isolation (COOP/COEP) และ Subresource Integrity (SRI) เพื่อยกระดับความปลอดภัยสูงสุด");
  }

  // 3. Build Stack-Tailored Remediation Code
  let language = "nginx";
  let code = "";

  if (isNextOrVercel) {
    language = "javascript";
    code = `// next.config.mjs (Generated 100% Locally — Zero External AI)
/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false, // ซ่อน X-Powered-By: Next.js
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          {
            key: "Content-Security-Policy",
            value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
          },
          { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), interest-cohort=()" },
          { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
        ],
      },
    ];
  },
};

export default nextConfig;`;
  } else if (isApache) {
    language = "apache";
    code = `# .htaccess (Generated 100% Locally — Zero External AI)
<IfModule mod_headers.c>
  Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests"
  Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
  Header always set X-Frame-Options "DENY"
  Header always set X-Content-Type-Options "nosniff"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
  Header always unset X-Powered-By
</IfModule>
ServerSignature Off

# ปิดกั้นการเข้าถึงไฟล์ความลับ (.env, .git)
<FilesMatch "^\\.(env|git)">
  Require all denied
</FilesMatch>${
      isPhpOrWp
        ? `

# WordPress / PHP Hardening: ปิดกั้น xmlrpc.php และซ่อนเวอร์ชัน PHP ใน php.ini (expose_php = Off)
<Files "xmlrpc.php">
  Require all denied
</Files>`
        : ""
    }`;
  } else if (isCloudflareOrNetlify && !isPhpOrWp) {
    language = "yaml";
    code = `# _headers for Cloudflare Pages / Netlify (Generated 100% Locally — Zero External AI)
/*
  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests
  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  Cross-Origin-Opener-Policy: same-origin`;
  } else {
    language = "nginx";
    code = `# nginx.conf (Generated 100% Locally — Zero External AI)
server {
    server_tokens off; # ซ่อนเลขเวอร์ชันของ nginx
    fastcgi_hide_header X-Powered-By;
    proxy_hide_header X-Powered-By;

    # Security Headers มาตรฐาน OWASP / MDN Observatory
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;

    # บล็อกการเข้าถึงไฟล์ .env และ .git
    location ~ /\\.(env|git) {
        deny all;
        return 404;
    }${
      isPhpOrWp
        ? `

    # PHP / WordPress Hardening: บล็อก xmlrpc.php และไฟล์ระบบไม่ให้ถูกเรียกตรง
    location = /xmlrpc.php {
        deny all;
        return 403;
    }
    # หมายเหตุ: ตั้งค่าใน php.ini เพิ่มเติม -> expose_php = Off และ disable_functions = exec,passthru,shell_exec,system`
        : ""
    }
}`;
  }

  return {
    grade: scan.grade,
    score: scan.score,
    summary,
    laymanSummary,
    findings: findings.slice(0, 6),
    language,
    code,
    mode: "local",
    anonymized: true,
  };
}

