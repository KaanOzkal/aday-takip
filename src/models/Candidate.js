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
    // models/Candidate.js içine ekle:

applicationForm: {
    // A. Kişisel
    birthPlace: { type: String, default: '' },
    maritalStatus: { type: String, default: '' },
    address: { type: String, default: '' },
    militaryService: { type: String, default: '' },
    drivingLicenseClass: { type: String, default: '' }, // Ehliyet Sınıfı
    
    // B. Eğitim & İş
    highSchool: { type: String, default: '' },
    university: { type: String, default: '' },
    workHistory: { type: String, default: '' }, // Tablo yerine metin olarak alacağız şimdilik

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
    levelAwareness: { type: String, default: '' }, // A2/B1 farkındalığı
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

    firstName: String,
    lastName: String,
    email: String,
    phone: String,
    job: String,
    location: String,
    targetState: { type: String, default: 'Belirtilmedi' }, 
    passportNo: String,
    applicationNo: String,
    applicationDate: { type: Date, default: Date.now },
    score: { type: Number, default: 90 },
    
    currentStage: { 
        type: String, 
        default: 'Başvuru Alındı' 
    },
    cvDetails: {
        profilePhoto: { type: String, default: '' },
        drivingLicense: { type: String, default: '' },
        summary: { type: String, default: '' }, // Hakkımda yazısı
        skills: { type: String, default: '' },  // Yetenekler
        languages: { type: String, default: '' }, // Diller
        experience1: { 
            title: String, company: String, date: String, desc: String 
        },
        experience2: { 
            title: String, company: String, date: String, desc: String 
        },
        education1: { 
            school: String, degree: String, date: String 
        }
    },

    // Alt şemalar
    documents: [documentSchema],
    appointments: [appointmentSchema],
    notes: [noteSchema] 

    

});



module.exports = mongoose.model('Candidate', candidateSchema);