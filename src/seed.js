const mongoose = require('mongoose');
const Candidate = require('./models/Candidate');

mongoose.connect('mongodb://localhost:27017/almanya_ats')
    .then(() => console.log('Veritabanına bağlanıldı...'))
    .catch(err => console.error('Bağlantı Hatası:', err));

// Senin gönderdiğin 40 kişilik liste
const rawData = [
   { id: 1, ad: "Veysi Irğar", meslek: "Kurye", durumId: 5, lokasyon: "Mardin", basvuruNo: "BER-2026-001", pasaport: "U27192985", telefon: "+90 555 555 55 55", email: "@email.com", puan: 85 },
   { id: 2, ad: "Umut Balkış", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Denizli", basvuruNo: "MUN-2026-002", pasaport: "U36039583", telefon: "+90 555 555 55 55", email: "mehmet@email.com", puan: 88 },
   { id: 3, ad: "Sami Koca", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Konya", basvuruNo: "HAM-2026-003", pasaport: "U36837917", telefon: "+90 555 555 55 55", email: "@email.com", puan: 90 },
   { id: 4, ad: "Mücahit Dinçer", meslek: "Tır Şoförü", durumId: 5, lokasyon: "istanbul", basvuruNo: "KOL-2026-004", pasaport: "U28059476", telefon: "+90 555 555 55 55", email: "@email.com", puan: 82 },
   { id: 5, ad: "Muammer Arslan", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İstanbul", basvuruNo: "FRA-2026-005", pasaport: "U38138827", telefon: "+90 555 555 55 55", email: "@email.com", puan: 88 },
   { id: 6, ad: "Mehmet Ozan Özmen", meslek: "Kurye", durumId: 5, lokasyon: "Ankara", basvuruNo: "STU-2026-006", pasaport: "U22433028", telefon: "+90 555 555 55 55", email: "@email.com", puan: 95 },
   { id: 7, ad: "Mehmet Emin Yaman", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İzmir", basvuruNo: "DUS-2026-007", pasaport: "U35565318", telefon: "+90 555 555 55 55", email: "@email.com", puan: 92 },
   { id: 8, ad: "Mahmut Sürhan Karadal", meslek: "Kurye", durumId: 5, lokasyon: "Adana", basvuruNo: "DOR-2026-008", pasaport: "U23636576", telefon: "+90 555 555 55 55", email: "@email.com", puan: 90 },
   { id: 9, ad: "Kerim İpek", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Niğde", basvuruNo: "ESS-2026-009", pasaport: "U25148300", telefon: "+90 555 555 55 55", email: "@email.com", puan: 85 },
   { id: 10, ad: "İsrafil Yılmaz", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Mersin", basvuruNo: "LEI-2026-010", pasaport: "U88050133", telefon: "+90 555 555 55 55", email: "@email.com", puan: 89 },
   { id: 11, ad: "İbrahim Can Eser", meslek: "Kurye", durumId: 5 , lokasyon: "Ankara", basvuruNo: "BRE-2026-011", pasaport: "U27946181", telefon: "+90 555 555 55 55", email: "@email.com", puan: 99 },
   { id: 12, ad: "Halil İbrahim Aras", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Diyarbakır", basvuruNo: "DRE-2026-012", pasaport: "U37493231", telefon: "+90 555 555 55 55", email: "@email.com", puan: 81 },
   { id: 13, ad: "Hakan Yiğit", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Adana", basvuruNo: "HAN-2026-013", pasaport: "U28910675", telefon: "+90 555 555 55 55", email: "@email.com", puan: 83 },
   { id: 14, ad: "Fatih Mustafa Alıravcı", meslek: "Kurye", durumId: 5, lokasyon: "İstanbul", basvuruNo: "NUR-2026-014", pasaport: "U23981375", telefon: "+90 555 555 55 55", email: "@email.com", puan: 86 },
   { id: 15, ad: "Ercan Ayata", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Osmaniye", basvuruNo: "DUI-2026-015", pasaport: "U15981690", telefon: "+90 555 555 55 55", email: "@email.com", puan: 87 },
   { id: 16, ad: "Doğan Bozkurt", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Antalya", basvuruNo: "BOC-2026-016", pasaport: "U26435423", telefon: "+90 555 555 55 55", email: "@email.com", puan: 91 },
   { id: 17, ad: "Burhanettin Irğar", meslek: "Kurye", durumId: 5, lokasyon: "Mardin", basvuruNo: "WUP-2026-017", pasaport: "U30274584", telefon: "+90 555 555 55 55", email: "@email.com", puan: 84 },
   { id: 18, ad: "Ali Yılmaz", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Gaziantep", basvuruNo: "BIE-2026-018", pasaport: "U32781709", telefon: "+90 555 555 55 55", email: "@email.com", puan: 92 },
   { id: 19, ad: "Ahmet Gök", meslek: "Kurye", durumId: 5, lokasyon: "Adana", basvuruNo: "BON-2026-019", pasaport: "U22798501", telefon: "+90 555 555 55 55", email: "@email.com", puan: 89 },
   { id: 20, ad: "Murat Koçcu", meslek: "Tır Şoförü", durumId: 4, lokasyon: "Konya", basvuruNo: "MUN-2026-020", pasaport: "U29925245", telefon: "+90 555 555 55 55", email: "@email.com", puan: 86 },
   { id: 21, ad: "Senai Kılıç", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Diyarbakır", basvuruNo: "KAR-2026-021", pasaport: "U88384327", telefon: "+90 555 555 55 55", email: "@email.com", puan: 85 },
   { id: 22, ad: "Can Yiğit Deveci", meslek: "Kurye", durumId: 5, lokasyon: "Ankara", basvuruNo: "MAN-2026-022", pasaport: "U35459456", telefon: "+90 555 555 55 55", email: "@email.com", puan: 87 },
   { id: 23, ad: "Emrah Ocak", meslek: "Kurye", durumId: 5, lokasyon: "Ordo", basvuruNo: "AUG-2026-023", pasaport: "U26894356", telefon: "+90 555 555 55 55", email: "@email.com", puan: 90 },
   { id: 24, ad: "Turgay Yiğit", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İzmir", basvuruNo: "WIE-2026-024", pasaport: "U88024920", telefon: "+90 555 555 55 55", email: "@email.com", puan: 93 },
   { id: 25, ad: "Orkun Misket", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Aydın", basvuruNo: "GEL-2026-025", pasaport: "U38466149", telefon: "+90 555 555 55 55", email: "@email.com", puan: 88 },
   { id: 26, ad: "Enes Uzun", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İstabul", basvuruNo: "MON-2026-026", pasaport: "U24465019", telefon: "+90 555 555 55 55", email: "@email.com", puan: 82 },
   { id: 27, ad: "Uğur Küçükhurman", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Manisa", basvuruNo: "BRA-2026-027", pasaport: "U23716873", telefon: "+90 555 555 55 55", email: "@email.com", puan: 84 },
   { id: 28, ad: "Cabbar Balkır", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İzmir", basvuruNo: "CHE-2026-028", pasaport: "U88277528", telefon: "+90 555 555 55 55", email: "@email.com", puan: 86 },
   { id: 29, ad: "Erdal Arslan", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Adıyaman", basvuruNo: "KIE-2026-029", pasaport: "U38115169", telefon: "+90 555 555 55 55", email: "@email.com", puan: 88 },
   { id: 30, ad: "Yılmaz Akdeniz", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İstanbul", basvuruNo: "MAG-2026-030", pasaport: "U29596300", telefon: "+90 555 555 55 55", email: "@email.com", puan: 90 },
   { id: 31, ad: "Muhammed Kürşad Demirci", meslek: "Kurye", durumId: 5, lokasyon: "Sivas", basvuruNo: "OBE-2026-031", pasaport: "U33945199", telefon: "+90 555 555 55 55", email: "@email.com", puan: 85 },
   { id: 32, ad: "Onur Orhan", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Kocaeli", basvuruNo: "LUB-2026-032", pasaport: "U88013159", telefon: "+90 555 555 55 55", email: "@email.com", puan: 86 },
   { id: 33, ad: "Alper Gümüş", meslek: "Kurye", durumId: 5, lokasyon: "Denizli", basvuruNo: "FRE-2026-033", pasaport: "U36125073", telefon: "+90 555 555 55 55", email: "@email.com", puan: 89 },
   { id: 34, ad: "Ferhat Konuk", meslek: "Kurye", durumId: 5, lokasyon: "İzmir", basvuruNo: "HAG-2026-034", pasaport: "U34437396", telefon: "+90 555 555 55 55", email: "@email.com", puan: 86 },
   { id: 35, ad: "Buket Atasayar", meslek: "Kurye", durumId: 5, lokasyon: "Bursa", basvuruNo: "ROS-2026-035", pasaport: "U30862420", telefon: "+90 555 555 55 55", email: "@email.com", puan: 83 },
   { id: 36, ad: "Ahmet Adın", meslek: "Kurye", durumId: 5, lokasyon: "Niğde", basvuruNo: "KAS-2026-036", pasaport: "U37396044", telefon: "+90 555 555 55 55", email: "@email.com", puan: 91 },
   { id: 37, ad: "Alper Koptur", meslek: "Kurye", durumId: 5, lokasyon: "Ankara", basvuruNo: "SAA-2026-037", pasaport: "U27276436", telefon: "+90 555 555 55 55", email: "@email.com", puan: 88 },
   { id: 38, ad: "Ramazan Gökhan Kına", meslek: "Kurye", durumId: 5, lokasyon: "Ankara", basvuruNo: "HAM-2026-038", pasaport: "U36187035", telefon: "+90 555 555 55 55", email: "@email.com", puan: 87 },
   { id: 39, ad: "Yasin Kavak", meslek: "Kurye", durumId: 5, lokasyon: "Konya", basvuruNo: "MUL-2026-039", pasaport: "U37950988", telefon: "+90 555 555 55 55", email: "@email.com", puan: 84 },
   { id: 40, ad: "Kaan Özkal", meslek: "Kurye", durumId: 5, lokasyon: "Ankara", basvuruNo: "MUL-2026-040", pasaport: "U12345678", telefon: "+90 555 555 55 55", email: "@email.com", puan: 100 }
];

const seedDB = async () => {
    // Önceki verileri temizle
    await Candidate.deleteMany({});
    console.log("Eski kayıtlar temizlendi.");

    // Verileri MongoDB formatına dönüştür
    const formattedCandidates = rawData.map(data => {
        // İsim Soyisim Ayırma Mantığı
        const nameParts = data.ad.split(' ');
        const lastName = nameParts.pop(); // Son parça soyisimdir
        const firstName = nameParts.join(' '); // Kalanlar isimdir

        // Durum ID Haritalama (Liste indexine göre)
        // 5. Index -> "Vize Başvurusu"
        const stages = [
            'Başvuru Alındı', 'Evrak Kontrolü', 'Tercüme Süreci', 
            'İşveren Onayı', 'Vize Hazırlığı', 'Vize Başvurusu', 
            'Seyahat Planı', 'Almanya\'da'
        ];
        
        // Eğer data.durumId 5 ise, listedeki 5. elemanı al
        const stageName = stages[data.durumId] || 'Başvuru Alındı';

        return {
            firstName: firstName,
            lastName: lastName,
            passportNo: data.pasaport,
            job: data.meslek,
            location: data.lokasyon,
            phone: data.telefon,
            email: data.email,
            applicationNo: data.basvuruNo,
            score: data.puan,
            currentStage: stageName,
            // Rastgele bir tarih olmasın, gerçek zamanlı olsun ya da verideki tarihi işleyebiliriz
            applicationDate: new Date() 
        };
    });

    await Candidate.insertMany(formattedCandidates);
    console.log("✅ 40 Adet Gerçekçi Aday Sisteme Eklendi!");
    
    // Test Verisi Göster
    console.log("\n--- TEST GİRİŞ BİLGİLERİ ---");
    console.log(`1. ${formattedCandidates[0].firstName} ${formattedCandidates[0].lastName} | Pasaport: ${formattedCandidates[0].passportNo}`);
    console.log(`2. ${formattedCandidates[39].firstName} ${formattedCandidates[39].lastName} | Pasaport: ${formattedCandidates[39].passportNo}`);

    mongoose.disconnect();
};

seedDB();