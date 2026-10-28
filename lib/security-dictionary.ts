export type FixDifficulty = "Easy" | "Medium" | "Hard";

export interface SecurityDictionaryEntry {
  title: string;
  simpleAnalogy: string;
  riskIfMissing: string;
  fixDifficulty: FixDifficulty;
}

const ENTRIES: Record<string, SecurityDictionaryEntry> = {
  csp: {
    title: "Content-Security-Policy (CSP)",
    simpleAnalogy:
      "เปรียบเสมือน 'รายชื่อแขกวีไอพีหน้างานคอนเสิร์ต' ที่กำหนดชัดเจนว่าอนุญาตให้โหลดสคริปต์ รูปภาพ หรือโค้ดจากแหล่งไหนเข้ามาทำงานบนหน้าเว็บได้บ้าง",
    riskIfMissing:
      "หากไม่ตั้งค่า แฮกเกอร์อาจแอบฝังสคริปต์อันตราย (XSS) ลงในหน้าเว็บเพื่อขโมยข้อมูลล็อกอินคุกกี้หรือดักจับรหัสผ่านของผู้ใช้งานโดยที่เจ้าของเว็บไม่รู้ตัว",
    fixDifficulty: "Hard",
  },
  hsts: {
    title: "Strict-Transport-Security (HSTS)",
    simpleAnalogy:
      "เปรียบเสมือน 'ป้ายบังคับขึ้นทางด่วนนิรภัย (HTTPS) เท่านั้น' ที่สั่งให้เบราว์เซอร์จำไว้เลยว่าห้ามแวะใช้ถนนสายเก่าที่ไม่มีการเข้ารหัส (HTTP) อีกเด็ดขาด",
    riskIfMissing:
      "ผู้ใช้อาจถูกโจมตีแบบลดระดับโปรโตคอล (SSL Stripping / Man-in-the-Middle) โดยเฉพาะเมื่อต่อ Wi-Fi สาธารณะ ทำให้คนร้ายดักฟังข้อมูลระหว่างทางได้",
    fixDifficulty: "Easy",
  },
  xfo: {
    title: "X-Frame-Options",
    simpleAnalogy:
      "เปรียบเสมือน 'กระจกกันแอบถ่ายซ้อนทับ' ที่ห้ามไม่ให้เว็บไซต์อื่นนำหน้าเว็บของคุณไปใส่ในกรอบใส (iframe) เพื่อหลอกให้คนกดปุ่มโดยไม่ตั้งใจ",
    riskIfMissing:
      "เสี่ยงต่อการโจมตีแบบ Clickjacking ที่มิจฉาชีพทำเว็บปลอมมาซ้อนทับปุ่มสำคัญ เช่น ปุ่มโอนเงิน ยืนยันสิทธิ์ หรือลบข้อมูล",
    fixDifficulty: "Easy",
  },
  xcto: {
    title: "X-Content-Type-Options",
    simpleAnalogy:
      "เปรียบเสมือน 'ฉลากระบุประเภทอาหารที่ห้ามเดาเอง' สั่งให้เบราว์เซอร์เชื่อตามประเภทไฟล์ที่เซิร์ฟเวอร์ระบุเท่านั้น ห้ามเดาสุ่มเปิดไฟล์รูปภาพเป็นไฟล์โปรแกรม",
    riskIfMissing:
      "เสี่ยงต่อการโจมตีแบบ MIME-Sniffing ที่แฮกเกอร์อัปโหลดไฟล์รูปภาพที่ซ่อนโค้ดอันตรายไว้ แล้วหลอกให้เบราว์เซอร์รันโค้ดนั้นเหมือนเป็นสคริปต์จริง",
    fixDifficulty: "Easy",
  },
  rp: {
    title: "Referrer-Policy",
    simpleAnalogy:
      "เปรียบเสมือน 'กติกามารยาทเวลาเดินออกจากบ้าน' ที่กำหนดว่าเวลาผู้ใช้คลิกลิงก์ออกไปเว็บอื่น จะบอกเว็บปลายทางไหมว่าเพิ่งเดินมาจากห้องไหนของเว็บเรา",
    riskIfMissing:
      "URL เต็มของหน้าเว็บภายใน (ซึ่งอาจมีรหัส Token รีเซ็ตรหัสผ่าน หรือข้อมูลค้นหาส่วนตัว) อาจรั่วไหลไปยังเว็บไซต์ภายนอกผ่านหัวข้อ HTTP Referer",
    fixDifficulty: "Easy",
  },
  pp: {
    title: "Permissions-Policy",
    simpleAnalogy:
      "เปรียบเสมือน 'แผงสวิตช์ตัดไฟอุปกรณ์ในบ้าน' ที่สั่งปิดสิทธิ์การใช้กล้อง ไมโครโฟน หรือพิกัด GPS ของเบราว์เซอร์ไว้ตั้งแต่ต้นหากเว็บไม่ได้ใช้งาน",
    riskIfMissing:
      "หากมีสคริปต์โฆษณาหรือโค้ดจากภายนอกหลุดเข้ามาในหน้าเว็บ โค้ดเหล่านั้นอาจพยายามขอสิทธิ์เข้าถึงกล้อง ไมโครโฟน หรือตำแหน่งที่ตั้งของผู้ใช้ได้",
    fixDifficulty: "Medium",
  },
  "/.env": {
    title: "Environment Configuration File (/.env)",
    simpleAnalogy:
      "เปรียบเสมือน 'สมุดจดรหัสเซฟและกุญแจบ้านทั้งหมด' ที่นักพัฒนาใช้เก็บค่าความลับของระบบ เช่น รหัสผ่านฐานข้อมูล และคีย์เชื่อมต่อระบบชำระเงิน",
    riskIfMissing:
      "วิกฤตสูงสุด! หากไฟล์ /.env เปิดให้คนทั่วไปดาวน์โหลดได้ แฮกเกอร์จะได้กุญแจเข้าถึงฐานข้อมูล เซิร์ฟเวอร์ และ API ภายนอกทั้งหมดทันที",
    fixDifficulty: "Easy",
  },
  "/.git": {
    title: "Git Repository Metadata (/.git & /.git/HEAD)",
    simpleAnalogy:
      "เปรียบเสมือน 'พิมพ์เขียวการสร้างบ้านและสมุดบันทึกการแก้ไขทุกขั้นตอน' ที่เก็บประวัติซอร์สโค้ดทั้งหมดของเว็บไซต์ตั้งแต่วันแรก",
    riskIfMissing:
      "แฮกเกอร์สามารถใช้เครื่องมือดูดโฟลเดอร์ /.git เพื่อดึงซอร์สโค้ดหลังบ้านทั้งหมดไปวิเคราะห์หาช่องโหว่ หรือค้นหารหัสผ่านที่เคยเผลอบันทึกไว้ในอดีต",
    fixDifficulty: "Easy",
  },
};

export const SECURITY_DICTIONARY: Record<string, SecurityDictionaryEntry> = {
  ...ENTRIES,
  "Content-Security-Policy": ENTRIES.csp,
  "Strict-Transport-Security": ENTRIES.hsts,
  "X-Frame-Options": ENTRIES.xfo,
  "X-Content-Type-Options": ENTRIES.xcto,
  "Referrer-Policy": ENTRIES.rp,
  "Permissions-Policy": ENTRIES.pp,
  "/.git/HEAD": ENTRIES["/.git"],
};

export function getSecurityDictionaryEntry(keyOrLabelOrPath: string): SecurityDictionaryEntry | undefined {
  return (
    SECURITY_DICTIONARY[keyOrLabelOrPath] ??
    SECURITY_DICTIONARY[keyOrLabelOrPath.toLowerCase()]
  );
}

