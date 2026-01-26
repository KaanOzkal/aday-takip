const mongoose = require('mongoose');
const LogisticsWord = require('./models/LogisticsWord');

mongoose.connect('mongodb://localhost:27017/almanya_ats')
    .then(() => console.log('Veritabanına bağlanıldı, kelimeler yükleniyor...'))
    .catch(err => console.error('Hata:', err));

const words = [
    { german: "Lieferung", turkish: "Teslimat", category: "Lojistik", exampleGerman: "Die Lieferung kommt heute.", exampleTurkish: "Teslimat bugün geliyor." },
    { german: "Anhänger", turkish: "Römork", category: "Araç", exampleGerman: "Der Anhänger ist voll.", exampleTurkish: "Römork dolu." },
    { german: "LKW", turkish: "Kamyon", category: "Araç", exampleGerman: "Der LKW fährt nach Berlin.", exampleTurkish: "Kamyon Berlin'e gidiyor." },
    { german: "Arbeitszeit", turkish: "Çalışma Süresi", category: "İş", exampleGerman: "Meine Arbeitszeit beginnt um 8 Uhr.", exampleTurkish: "Mesaim saat 8'de başlıyor." },
    { german: "Kollege", turkish: "İş Arkadaşı", category: "İş", exampleGerman: "Mein Kollege ist freundlich.", exampleTurkish: "İş arkadaşım dost canlısıdır." },
    { german: "Frachtbrief", turkish: "Navlun Senedi", category: "Belge", exampleGerman: "Wo ist der Frachtbrief?", exampleTurkish: "Navlun senedi nerede?" },
    { german: "Zoll", turkish: "Gümrük", category: "Sınır", exampleGerman: "Wir müssen durch den Zoll.", exampleTurkish: "Gümrükten geçmeliyiz." },
    { german: "Stau", turkish: "Trafik Sıkışıklığı", category: "Yol", exampleGerman: "Es gibt einen Stau auf der A7.", exampleTurkish: "A7 yolunda trafik var." },
    { german: "Gabelstapler", turkish: "Forklift", category: "Depo", exampleGerman: "Der Gabelstapler hebt die Palette.", exampleTurkish: "Forklift paleti kaldırıyor." },
    { german: "Unfall", turkish: "Kaza", category: "Acil", exampleGerman: "Ich hatte einen kleinen Unfall.", exampleTurkish: "Ufak bir kaza geçirdim." },
    { german: "Werkstatt", turkish: "Tamirhane", category: "Bakım", exampleGerman: "Der LKW muss in die Werkstatt.", exampleTurkish: "Kamyonun servise gitmesi lazım." },
    { german: "Pünktlich", turkish: "Zamanında", category: "Genel", exampleGerman: "Sei bitte pünktlich.", exampleTurkish: "Lütfen zamanında ol." },
    { german: "Vertrag", turkish: "Sözleşme", category: "İş", exampleGerman: "Ich habe den Vertrag unterschrieben.", exampleTurkish: "Sözleşmeyi imzaladım." },
    { german: "Feierabend", turkish: "Paydos", category: "İş", exampleGerman: "Wann machst du Feierabend?", exampleTurkish: "Ne zaman paydos ediyorsun?" },
    { german: "Lager", turkish: "Depo", category: "Lojistik", exampleGerman: "Die Ware ist im Lager.", exampleTurkish: "Malzemeler depoda." }
];

const seedWords = async () => {
    await LogisticsWord.deleteMany({}); // Eskileri temizle
    await LogisticsWord.insertMany(words);
    console.log("✅ Kelime havuzu başarıyla yüklendi!");
    mongoose.disconnect();
};

seedWords();