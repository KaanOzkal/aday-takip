// --- ALMANCA CÜMLELERİ YÜKLEME ROTASI (DÜZELTİLDİ) ---
app.get('/seed-german', async (req, res) => {
    try {
        const sentences = [
            { 
                german: "Fracht",   // 'word' yerine 'german' yaptık
                turkish: "Yük",     // 'meaning' yerine 'turkish' yaptık
                category: "Lojistik",
                exampleGerman: "Die Fracht muss pünktlich sein.", 
                exampleTurkish: "Yük zamanında olmalı." 
            },
            { 
                german: "Gabelstapler", 
                turkish: "Forklift", 
                category: "Depo",
                exampleGerman: "Der Gabelstapler hebt die schwere Palette.", 
                exampleTurkish: "Forklift ağır paleti kaldırıyor." 
            },
            { 
                german: "Polizei", 
                turkish: "Polis", 
                category: "Acil",
                exampleGerman: "Rufen Sie bitte die Polizei.", 
                exampleTurkish: "Lütfen polisi arayın." 
            },
            { 
                german: "Erste-Hilfe", 
                turkish: "İlk Yardım", 
                category: "Acil",
                exampleGerman: "Wo ist der Erste-Hilfe-Kasten?", 
                exampleTurkish: "İlk yardım çantası nerede?" 
            },
            { 
                german: "Ausfahrt", 
                turkish: "Çıkış", 
                category: "Trafik",
                exampleGerman: "Nehmen Sie die nächste Ausfahrt.", 
                exampleTurkish: "Bir sonraki çıkıştan çıkın." 
            }
        ];

        // İsteğe bağlı: Önce eski örnekli olanları temizle ki çift kayıt olmasın
        // await LogisticsWord.deleteMany({ exampleGerman: { $exists: true } });

        await LogisticsWord.insertMany(sentences);

        res.send(`
            <div style="text-align:center; padding:50px; font-family:sans-serif;">
                <h1 style="color:green;">✅ Düzeltildi ve Yüklendi!</h1>
                <p>Kelimeler ve Cümleler veritabanına başarıyla işlendi.</p>
                <a href="/panel" style="background:#333; color:white; padding:10px 20px; text-decoration:none; border-radius:5px;">Panele Dön</a>
            </div>
        `);

    } catch (error) {
        res.send("Yine Hata Oldu: " + error.message);
    }
});