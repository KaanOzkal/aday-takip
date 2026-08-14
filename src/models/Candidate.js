const mongoose = require('mongoose');

const documentSchema = new mongoose.Schema({
    name: String,
    filename: String,
    driveLink: String,
    fileId: String,
    status: { type: String, enum: ['İnceleniyor', 'Onaylandı', 'Reddedildi'], default: 'İnceleniyor' },
    date: { type: Date, default: Date.now }
});

const appointmentSchema = new mongoose.Schema({
    date: String,
    time: String,
    type: String,
    status: { type: String, enum: ['Beklemede', 'Onaylandı', 'Reddedildi'], default: 'Beklemede' },
    createdAt: { type: Date, default: Date.now }
});

const noteSchema = new mongoose.Schema({
    content: String,
    author: { type: String, default: 'Admin' },
    date: { type: Date, default: Date.now }
});

const candidateSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: { type: String, required: true },
    password: { type: String, required: true }, 
    phoneNumber: { type: String, default: '' }, 
    
    job: String,
    location: String,
    targetState: { type: String, default: 'Belirtilmedi' }, 
    passportNo: String,
    applicationNo: String,
    score: { type: Number, default: 90 },
    
    currentStage: { type: String, default: 'Başvuru Alındı' }, 
    germanyStage: { type: String, default: '1. Başvuru ve Kayıt' }, 
    company: { type: String, default: 'Atanmadı' }, 

    // 👇 YENİ: ALMANYA ENTEGRASYON SÜREÇLERİ
    integrationSteps: {
        telefonTemini: { type: Boolean, default: false },
        lojmanYerlesimi: { type: Boolean, default: false },
        genelEntegrasyon: { type: Boolean, default: false },
        bankaHesabi: { type: Boolean, default: false },
        kod95: { type: Boolean, default: false },
        saglikSigortasi: { type: Boolean, default: false },
        anmeldung: { type: Boolean, default: false },
        dilKursu: { type: Boolean, default: false }
    },

    applicationDate: { type: Date, default: Date.now },

    applicationForm: {
        birthPlace: { type: String, default: '' },
        maritalStatus: { type: String, default: '' },
        address: { type: String, default: '' },
        militaryService: { type: String, default: '' },
        drivingLicenseClass: { type: String, default: '' }, 
        highSchool: { type: String, default: '' },
        university: { type: String, default: '' },
        workHistory: { type: String, default: '' },
        meaningOfJob: { type: String, default: '' },
        dailyRoutine: { type: String, default: '' },
        germanyDesire: { type: String, default: '' },
        definitionDiff: { type: String, default: '' },
        challenges: { type: String, default: '' },
        languageImportance: { type: String, default: '' },
        friendsInGermany: { type: String, default: '' },
        germanLevel: { type: String, default: '' },
        germanEducationPlace: { type: String, default: '' },
        levelAwareness: { type: String, default: '' },
        languagePlan: { type: String, default: '' },
        failPlan: { type: String, default: '' },
        budgetForCourse: { type: String, default: '' },
        familyLanguage: { type: String, default: '' },
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
        berlinerMeet: { type: String, default: '' },
        berlinerKnowledge: { type: String, default: '' },
        berlinerTrust: { type: String, default: '' },
        berlinerSocial: { type: String, default: '' }
    },

    cvDetails: {
        profilePhoto: { type: String, default: "" },
        summary: { type: String, default: "" },
        email: String,
        phone: String,
        address: String,
        birthDate: String,
        nationality: String,
        drivingLicense: String,
        linkedin: String,
        skills: { type: String, default: "" },          
        languages: { type: String, default: "" },       
        technicalSkills: { type: String, default: "" }, 
        softSkills: { type: String, default: "" },
        experience1: { title: String, company: String, date: String, location: String, desc: String },
        experience2: { title: String, company: String, date: String, location: String, desc: String },
        exp_additional_title: [String],
        exp_additional_company: [String],
        exp_additional_date: [String],
        exp_additional_location: [String],
        exp_additional_desc: [String],  
        education1: { school: String, degree: String, date: String, location: String, achievements: String },
        edu_additional_school: [String],
        edu_additional_degree: [String],
        edu_additional_date: [String],
        edu_additional_location: [String],
        certificate1: String,
        certificate1_issuer: String,
        certificate1_date: String,
        certificate1_validity: String,
        cert_additional_name: [String],
        cert_additional_issuer: [String],
        cert_additional_date: [String],
        cert_additional_validity: [String],
        reference1_name: String,
        reference1_position: String,
        reference1_company: String,
        reference1_contact: String,
        cvColor: { type: String, default: '#0f172a' },
        themeName: { type: String, default: 'Koyu Profesyonel' }
    },

    documents: [documentSchema],
    appointments: [appointmentSchema],
    notes: [noteSchema]

});

module.exports = mongoose.model('Candidate', candidateSchema);