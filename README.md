# powershell-gdrive

This script can perform differential Backup and folder syncronization Powershell script for Google Drive
Diffirential backup is a cumulative backup of all changes made since the last full or normal backup, i.e., the differences since the last full backup.
You can have fill backup as as many as you wish differential backups.Whenever you need to restore your files to certain moment in past, combine last fullbackup with the differential backup made at desired point it time.
For additional resiliency against network failures and the script supports resumable uploads and multipart uploads for small files
Exponentiall backoff stragety is used in case of network failure, so the script can work unattended.
The script prunes old backups with predefined time interval, hardcoded in the script within variable $Days_to_Keep_Backup. Currently it is set to 30. You may set it no any other value of your choice.

# Usage
To run script, clone the repo, then download standalone command line version of 7zip utility, located here https://www.7-zip.org/download.html and place it into the script folder

Next, register the script as an application of your choice under https://console.developers.google.com Use http://localhost:8080/gdriveauthcallback for app callback.
It is nesessary for getting refresh token first time app starts, users will be asked to explicitly give/deny permission for the script to acess drive files.

Download client secret for your app, save it as client_secret.json in the script folder.

Next, add folders included into backup or excluded from it into includes.txt annd excludes.txt text files.
Run the bat file gdrive_backup_and_sync.bat with full agrument for full backup, or with diff option for differential from last succesfull backup made.
Run bat file without parameters to see available run options.
