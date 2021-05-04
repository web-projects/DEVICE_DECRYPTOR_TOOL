:: ASSUMPTION: BASE PYTHON IS IN C:\Python
:: Modify as needed for your configuration
::

@if "%1"=="" goto USAGE

:: COMPORT AS PARAMETER
@set COMPORT=%1
@if NOT "%COMPORT:~0,3%"=="COM" GOTO USAGE

@if "%2"=="CAPK" goto CAPK

:NEXTSTEP
::@set TARGER_DIR="upload\config\cless"

::@set TARGER_DIR="upload\configjt\unattended"
::@set TARGER_DIR="upload\configjt\attended"

:: ICC CONFIGS
@set TARGER_DIR="upload\config\emv\ICC\attended"
::@set TARGER_DIR="upload\config\emv\ICC\unattended"
::@set TARGER_DIR="upload\config\emv\ICC\test"

::@set TARGER_DIR="upload\config\emv\ICC\attended\old"
goto UPLOAD

:: CAPK FILES
:CAPK
@set TARGER_DIR="upload\config\emv\ICC\capk"
goto UPLOAD

:: TTQ - MSD
:TTQ
::@set TARGER_DIR="upload\config\emv\TTQ"

:UPLOAD
@SET /A COUNT=0
@for /r %%i in (%TARGER_DIR%\*) do (
  putfile.py --file %%i --serial %COMPORT%
  @SET /A COUNT+=1
)
@ECHO.
@ECHO FILES UPLOADED: %COUNT%
@ECHO.

@GOTO END

:USAGE
@echo.
@echo USAGE: %0 COMXX
@echo.

:END
@echo.
@set COMPORT=
@set COUNT=