const mongoose = require('mongoose');

// --- 1. DOKÜMAN ALT ŞEMASI ---
const documentSchema = new mongoose.Schema({
    name: String,
    filename: String,
    driveLink: String,
    fileId: String,
    status: { 
        type: String, 
        enum: ['İnceleniyor', 'Onaylandı', 'Reddedildi'], 
        default: 'İnceleniyor' 
    },
    date: { type: Date, default: Date.now }
});

// --- 2. RANDEVU ALT ŞEMASI ---
const appointmentSchema = new mongoose.Schema({
    date: String,
    time: String,
    type: String,
    status: { 
        type: String, 
        enum: ['Beklemede', 'Onaylandı', 'Reddedildi'], 
        default: 'Beklemede' 
    },
    createdAt: { type: Date, default: Date.now }
});

// --- 3. NOTLAR ALT ŞEMASI ---
const noteSchema = new mongoose.Schema({
    content: String,
    author: { type: String, default: 'Admin' },
    date: { type: Date, default: Date.now }
});

// --- 4. ANA ADAY ŞEMASI ---
const candidateSchema = new mongoose.Schema({
    
    // Temel Bilgiler
    firstName: String,
    lastName: String,
    email: { type: String, required: true },
    password: { type: String, required: true }, // Giriş için zorunlu
    phoneNumber: { type: String, default: '' }, // SMS Bildirimleri için
    
    // Durum Bilgileri
    job: String,
    location: String,
    targetState: { type: String, default: 'Belirtilmedi' }, 
    passportNo: String,
    applicationNo: String,
    score: { type: Number, default: 90 },
    currentStage: { type: String, default: 'Başvuru Alındı' },
    applicationDate: { type: Date, default: Date.now },

    // --- A. BAŞVURU FORMU (Application Form) ---
    applicationForm: {
        // A. Kişisel
        birthPlace: { type: String, default: '' },
        maritalStatus: { type: String, default: '' },
        address: { type: String, default: '' },
        militaryService: { type: String, default: '' },
        drivingLicenseClass: { type: String, default: '' }, 
        
        // B. Eğitim & İş
        highSchool: { type: String, default: '' },
        university: { type: String, default: '' },
        workHistory: { type: String, default: '' },

        // C. Mesleki Motivasyon
        meaningOfJob: { type: String, default: '' },
        dailyRoutine: { type: String, default: '' },
        germanyDesire: { type: String, default: '' },
        definitionDiff: { type: String, default: '' },
        challenges: { type: String, default: '' },
        languageImportance: { type: String, default: '' },
        friendsInGermany: { type: String, default: '' },

        // D. Dil
        germanLevel: { type: String, default: '' },
        germanEducationPlace: { type: String, default: '' },
        levelAwareness: { type: String, default: '' },
        languagePlan: { type: String, default: '' },
        failPlan: { type: String, default: '' },
        budgetForCourse: { type: String, default: '' },
        familyLanguage: { type: String, default: '' },

        // E. Almanya Motivasyonu
        migrationTime: { type: String, default: '' },
        cityChoice: { type: String, default: '' },
        cityFlexibility: { type: String, default: '' },
        expertiseArea: { type: String, default: '' },
        germanyKnowledge: { type: String, default: '' },
        germanyChallenges: { type: String, default: '' },
        expectations: { type: String, default: '' },
        familyBring: { type: String, default: '' },
        accommodation: { type: String, default: '' },
        migrationBudget: { type: String, default: '' },
        visitHistory: { type: String, default: '' },

        // F. Berliner
        berlinerMeet: { type: String, default: '' },
        berlinerKnowledge: { type: String, default: '' },
        berlinerTrust: { type: String, default: '' },
        berlinerSocial: { type: String, default: '' }
    },

    // --- B. CV DETAYLARI (Gelişmiş Yapı) ---
    cvDetails: {
        // Profil
        profilePhoto: { type: String, default: "" },
        summary: { type: String, default: "" },
        
        // İletişim (CV'ye özel override)
        email: String,
        phone: String,
        address: String,
        birthDate: String,
        nationality: String,
        drivingLicense: String,
        linkedin: String,

        // Yetenekler
        skills: { type: String, default: "" },          
        languages: { type: String, default: "" },       
        technicalSkills: { type: String, default: "" }, 
        softSkills: { type: String, default: "" },

        // Sabit İş Deneyimleri
        experience1: {
            title: String, company: String, date: String, location: String, desc: String
        },
        experience2: {
            title: String, company: String, date: String, location: String, desc: String
        },

        // DİNAMİK EK İŞ DENEYİMLERİ (Array)
        exp_additional_title: [String],
        exp_additional_company: [String],
        exp_additional_date: [String],
        exp_additional_location: [String],
        exp_additional_desc: [String],

        // Sabit Eğitim
        education1: {
            school: String, degree: String, date: String, location: String, achievements: String
        },

        // DİNAMİK EK EĞİTİMLER (Array)
        edu_additional_school: [String],
        edu_additional_degree: [String],
        edu_additional_date: [String],
        edu_additional_location: [String],

        // Sertifikalar (Sabit ve Dinamik)
        certificate1: String,
        certificate1_issuer: String,
        certificate1_date: String,
        certificate1_validity: String,

        cert_additional_name: [String],
        cert_additional_issuer: [String],
        cert_additional_date: [String],
        cert_additional_validity: [String],

        // Referanslar
        reference1_name: String,
        reference1_position: String,
        reference1_company: String,
        reference1_contact: String,

        // Tasarım
        cvColor: { type: String, default: '#0f172a' },
        themeName: { type: String, default: 'Koyu Profesyonel' }
    },

    // Alt Şemalar
    documents: [documentSchema],
    appointments: [appointmentSchema],
    notes: [noteSchema]

});

module.exports = mongoose.model('Candidate', candidateSchema);