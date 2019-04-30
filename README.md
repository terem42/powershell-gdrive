# powershell-gdrive
Differential Backup and folder syncronization Powershell script for Google Drive. Supports resumable upload of large files, very useful in case of unstable connection. 
To use script, first download 7zip commandline from here: https://www.7-zip.org/download.html, place executable in in script folder.

Next, register the script as an application of your choice under https://console.developers.google.com Use http://localhost:8080/gdriveauthcallback for app callback.
It is nesessary for getting refresh token first time app starts, users will be asked to explicitly give/deny permission for the script to acess drive files.
Download client secret for your app, save it as client_secret.json in the script folder.

Run bat file without parameters to see available run options.
