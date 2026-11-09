@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================
echo   BERLINER - GitHub'a gonderiliyor
echo ============================================
echo.
git status --short
echo.
git add -A
git reset -q -- github_gonder.bat
git commit -m "Admin ve aday panelini yenile, calismayan fonksiyonlari duzelt" -m "- Admin paneli: kenar menu, genel bakis, aday arama/filtre/toplu islem, aday detay sayfasi, CSV disa aktarma" -m "- Aday portali: yeni giris ekrani, ana sayfa, belgeler, randevular, mesajlar, surec, ayarlar, yardim" -m "- Duzeltmeler: aday ekleme, not silme, belge goruntuleme, ilerleme hesabi, ayarlar kaydi, seed rotalari korumasi" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -m "Claude-Session: https://claude.ai/code/session_012iq7XDjZ8oErFg6AgJjLGF"
echo.
git push origin main
echo.
if %errorlevel%==0 (echo [OK] GitHub'a basariyla gonderildi.) else (echo [HATA] Gonderim basarisiz. Yukaridaki mesaji kontrol edin.)
echo.
pause
