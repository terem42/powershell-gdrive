$PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
[Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US';
[void][System.Reflection.Assembly]::LoadWithPartialName('System.Web.Extensions')

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls

$proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

$7zip = "$PSScriptRoot\7za.exe"

$backupOutputPath = "$PSScriptRoot\backup_local"
$remote_backup_folder = "notebook_backup"
$excludesFile = "$PSScriptRoot\excludes.txt" 
$includesFile = "$PSScriptRoot\includes.txt"

$binding_url = "http://localhost:8080/"
$oauth_listener_endpoint  = "/gdriveauthcallback"

$script:csecret = @{}

$client_secret_filename = "client_secret.json"
$client_refresh_token_filename = "refresh_token.json"
$resumable_transfer_state_filename = "resumable_transfer_state.json"
$Days_to_Keep_Backup = 30

#-----------------functions ------------------------

function ConvertFrom-Json([String]$str) {    
    $ds = New-Object System.Web.Script.Serialization.JavaScriptSerializer 
    return $ds.DeserializeObject($str)
}


function post-urlencoded-req($requestUrl, $params_hash) {
    Write-Host "URL = $requestUrl ---"
    [string]$GAuthBody = ""
    foreach($entry in $params_hash.GetEnumerator()) {
      if ($GAuthBody.Length -gt 0) { $GAuthBody += "&" }
      $GAuthBody += $entry.Name + "=" + [URI]::EscapeDataString([string]$entry.Value)
    } 
    Write-Host "URLencoded param list to send = $GAuthBody"
    $wr = [System.Net.HttpWebRequest]::Create($requestUrl)
    $wr.Proxy = $proxy
    $wr.Method= 'POST';
    $wr.ContentType="application/x-www-form-urlencoded; charset=utf-8";
    $Body = [byte[]][char[]]$GAuthBody;
    $wr.Timeout = 10000;
   [void]$resp  
   [void]$exception_status
   [void]$respTxt
  $repeat_op = $False
  $req_loop_attempts = 0
  do {
  try { 
    $Stream = $wr.GetRequestStream();
    $Stream.Write($Body, 0, $Body.Length);
    $Stream.Flush();
    $Stream.Close();
    $resp = $wr.GetResponse()
    $rst = $resp.GetResponseStream()
    $sr = New-Object System.IO.StreamReader($rst)
    $respTxt = $sr.ReadToEnd()
    $rst.Close()
    $exception_status = [System.Net.WebExceptionStatus]::Success
   }
   catch [Net.WebException] 
   { 
            $exception_status = $_.Exception.Status
            Write-Host "got exception status $exception_status"   
            if ($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError) {
             $resp = [System.Net.HttpWebResponse] $_.Exception.Response
             Write-Host "HTTP response code = $([int]$resp.StatusCode)"
             if (!([int]$resp.StatusCode -eq 403 -Or [int]$resp.StatusCode -eq 401)) {
              for($i=0; $i -lt $resp.Headers.Count; $i++) { 
	        Write-Host "\nHeader Name:$($resp.Headers.Keys[$i]), Value :$($resp.Headers[$i])"
              } 
             }
            }  else {
               Write-Host "connection issue: status = $($_.Exception.Status)"               
            } 
   }
#   Write-Host "in loop exception status $exception_status"   
   $repeat_op =  ($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError `
                 -And !([int]$resp.StatusCode -eq 403 -Or [int]$resp.StatusCode -eq 401)) `
                 -Or (!($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError) -And !($exception_status -eq [System.Net.WebExceptionStatus]::Success))
   if ($repeat_op) {
     $req_loop_attempts++
     $delay = $(calculate_backoff_delay $req_loop_attempts)
     Write-Host "error, repeating the operation in $delay seconds"
     Start-Sleep -s $delay
   }
   } while ($repeat_op)

    
   if ($exception_status -eq [System.Net.WebExceptionStatus]::Success) {
     if (![STRING]::IsNullOrEmpty($respTxt)) {
       Write-Host $respTxt
       @{"httpStatusCode" = $([int]$resp.StatusCode); "json" = ConvertFrom-Json($respTxt) }
     } else {
       @{"httpStatusCode" = $([int]$resp.StatusCode); "json" = @{} }
     }
   } elseif ($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError) {
     @{"httpStatusCode" = $([int]$resp.StatusCode); "json" = @{} }
   } else { 
     @{"httpStatusCode" = [int]$exception_status; "json" = @{} } 
   }
   
}

function upload-file-from-bytebuf-in-one-req($parent_folder_id, $file_descriptor, $byte_buffer, $byte_buffer_length, $overwrite, $remote_file_id) {
    $enc = [System.Text.Encoding]::GetEncoding("UTF-8")
    $upload_url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart"
    if ($overwrite) { $upload_url = "https://www.googleapis.com/upload/drive/v3/files/$($remote_file_id)?uploadType=multipart"}
    Write-Host "upload url = $upload_url"
    $wr = [System.Net.HttpWebRequest]::Create($upload_url)
    $wr.Proxy = $proxy
    $wr.Method= 'POST';
    if ($overwrite) { $wr.Method = "PATCH" }
    $file_ContentType = "application/octet-stream"
    $file_extension = $file_descriptor.Extension.Substring(1)
    if ($MIMEHASH.ContainsKey($file_extension))
    { 
      $file_ContentType = $MIMEHASH.Item($file_extension)
    }
    $boundary = [guid]::NewGuid().ToString()
    $wr.ContentType="multipart/mixed; boundary=$boundary";
    $wr.Timeout = 10000;
    $wr.Headers.Add("Authorization: Bearer $($script:session_auth_token)")

    $req_head = @"
--${boundary}
Content-Type: application/json; charset=UTF-8`r`n`r`n{
  "name": "$($file_descriptor.Name)",
  "createdTime": "$($file_descriptor.CreationTimeUtc.toString("yyyy-MM-ddTHH:mm:ss.fffZ"))",
  "modifiedTime": "$($file_descriptor.LastWriteTimeUtc.toString("yyyy-MM-ddTHH:mm:ss.fffZ"))",
  "parents": ["$($parent_folder_id)"]
}

--${boundary}
Content-Type: ${file_ContentType}`r`n`r`n
"@
    if ($overwrite) {
    $req_head = @"
--${boundary}
Content-Type: application/json; charset=UTF-8`r`n`r`n{

}

--${boundary}
Content-Type: ${file_ContentType}`r`n`r`n
"@
    }
    $req_tail = "`r`n--${boundary}--"

    $req_head_bytes = $enc.GetBytes($req_head);
    $req_tail_bytes = $enc.GetBytes($req_tail);
    
    $total_req_body_length = $req_head_bytes.length + $byte_buffer_length + $req_tail_bytes.length
    $wr.ContentLength = $total_req_body_length 
   [void]$resp
   [void]$exception_status
   [void]$respTxt
  try {   
    $Stream = $wr.GetRequestStream();    
    $Stream.Write($req_head_bytes,0,$req_head_bytes.length);
    $Stream.Write($byte_buffer, 0, $byte_buffer_length);
    $Stream.Write($req_tail_bytes,0,$req_tail_bytes.length);
    $Stream.Flush();
    $Stream.Close();
    $resp = $wr.GetResponse()
    $rs = $resp.GetResponseStream()
    $sr = New-Object System.IO.StreamReader($rs)
    $respTxt = $sr.ReadToEnd()
    $rs.Close()
    $exception_status = [System.Net.WebExceptionStatus]::Success
   }
   catch [Net.WebException] 
   { 
            $exception_status = $_.Exception.Status
            Write-Host "upload file in one req exception status=$exception_status"
            if ($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError) {
             $resp = [System.Net.HttpWebResponse] $_.Exception.Response
             if (!([int]$resp.StatusCode -eq 4403 -Or [int]$resp.StatusCode -eq 401)) {
             Write-Host "got error response from server, status returned $($resp.StatusCode)"
              for($i=0; $i -lt $resp.Headers.Count; $i++) { 
	        Write-Host "\nHeader Name:$($resp.Headers.Keys[$i]), Value :$($resp.Headers[$i])"
              }
               $ResponseStream = $resp.GetResponseStream()
               $ReadStream = New-Object System.IO.StreamReader $ResponseStream
               $respExTxt=$ReadStream.ReadToEnd()
               $ResponseStream.Close()
               Write-Host "exception response HTTP body = $respExTxt"
             }
            }  else {
               Write-Host "connection issue: status = $($_.Exception.Status)"               
            } 
   }

   if ($exception_status -eq [System.Net.WebExceptionStatus]::Success) {
     @{"httpStatusCode" = $([int]$resp.StatusCode); "file_metadata" = $respTxt}
   } elseif ($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError) { @{"httpStatusCode" = $([int]$resp.StatusCode)} }
   else { @{"httpStatusCode" = [int]$exception_status} }
}

function start-resumable-file-upload-req($parent_folder_id, $file_descriptor, $overwrite, $remote_file_id) {
   Write-Host "initiating resumable request"
   $enc =  [System.Text.Encoding]::GetEncoding("UTF-8")
   [void]$resp
   [void]$exception_status
   [void]$respTxt
   try {
    $upload_url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable"
    if ($overwrite) { $upload_url = "https://www.googleapis.com/upload/drive/v3/files/$($remote_file_id)?uploadType=resumable"}
    Write-Host "upload url = $upload_url"
    $wr = [System.Net.HttpWebRequest]::Create($upload_url)
    $wr.Proxy = $proxy
    $wr.Method= 'POST';
    if ($overwrite) { $wr.Method = "PATCH" }
    $wr.ContentType="application/json; charset=UTF-8";
    $wr.Timeout = 10000;
    $wr.Headers.Add("Authorization: Bearer $($script:session_auth_token)")
    $wr.Headers.Add("X-Upload-Content-Type: application/data")
    $wr.Headers.Add("X-Upload-Content-Length: $($file_descriptor.length)")
    $req_body = @"
{
  "name": "$($file_descriptor.Name)",
  "createdTime": "$($file_descriptor.CreationTimeUtc.toString("yyyy-MM-ddTHH:mm:ss.fffZ"))",
  "modifiedTime": "$($file_descriptor.LastWriteTimeUtc.toString("yyyy-MM-ddTHH:mm:ss.fffZ"))",
  "parents": ["${parent_folder_id}"]
}
"@
    if ($overwrite) {
    $req_body = @"
{

}
"@
    }
    $req_body_bytes = $enc.GetBytes($req_body);
    $total_req_body_length = $req_body_bytes.length
    Write-Host "total req body length = $total_req_body_length"
    $wr.ContentLength = $total_req_body_length
    $Stream = $wr.GetRequestStream();    
    $Stream.Write($req_body_bytes,0,$req_body_bytes.length);
    $Stream.Flush();
    $Stream.Close();
    $resp = $wr.GetResponse()
    $resp_stream = $wr.GetResponse().GetResponseStream()
    $sr = New-Object System.IO.StreamReader($resp_stream)
    $respTxt = $sr.ReadToEnd()
    $resp_stream.Close()
    $exception_status = [System.Net.WebExceptionStatus]::Success
   }
   catch [Net.WebException] 
   { 
            $exception_status = $_.Exception.Status
            if ($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError) {
             $resp = [System.Net.HttpWebResponse] $_.Exception.Response
             if (!([int]$resp.StatusCode -eq 403 -Or [int]$resp.StatusCode -eq 401)) {
             Write-Host "got error response from server, status returned $($resp.StatusCode)"
              for($i=0; $i -lt $resp.Headers.Count; $i++) { 
	        Write-Host "\nHeader Name:$($resp.Headers.Keys[$i]), Value :$($resp.Headers[$i])"
              } 
             }
            }  else {
               Write-Host "connection issue: status = $($_.Exception.Status)"               
            } 
   }
   if ($exception_status -eq [System.Net.WebExceptionStatus]::Success) {
     [System.IO.File]::WriteAllText("$PSScriptRoot\$resumable_transfer_state_filename", "{`"filepath`": `"$($file_descriptor.FullName -replace "\\" , "\\")`",`"url`" : `"$($resp.Headers["Location"])`"}")
     @{"httpStatusCode" = $([int]$resp.StatusCode); "resumable_location" = $($resp.Headers["Location"]); "file_metadata" = $respTxt}
     Write-Host $resp.Headers["Location"]
   } elseif ($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError) { @{"httpStatusCode" = $([int]$resp.StatusCode)} }
   else { @{"httpStatusCode" = [int]$exception_status} }
}

function upload-resumable-file-chunk-req($resumable_location,
                               $range_start,$range_end,
                               $file_name, $file_length,
                               $byte_buffer, $byte_buffer_length) {
    Write-Host "sending another chunk of file"
    $enc = [System.Text.Encoding]::GetEncoding("UTF-8")
    [void]$resp
    [void]$exception_status
    [void]$respTxt
   try {
    $wr = [System.Net.HttpWebRequest]::Create($resumable_location)
    $wr.Proxy = $proxy
    $wr.Method= 'PUT';
    $wr.Timeout = 10000;
    $wr.Headers.Add("Authorization: Bearer $($script:session_auth_token)")
    $wr.ContentLength = $byte_buffer_length
    $buf_str = $enc.GetString($byte_buffer)
    Write-Host "byte_buffer_length=$byte_buffer_length"
    Write-Host "Content-Range: bytes ${range_start}-${range_end}/${file_length}"
    $wr.Headers.Add("Content-Range: bytes ${range_start}-${range_end}/${file_length}")
    $Stream = $wr.GetRequestStream();    
    $Stream.Write($byte_buffer,0,$byte_buffer_length);
    $Stream.Flush();
    $Stream.Close();
    $resp = $wr.GetResponse()
    $resp_stream = $resp.GetResponseStream()
    $sr = New-Object System.IO.StreamReader($resp_stream)
    $respTxt = $sr.ReadToEnd()
    $resp_stream.Close()
    $exception_status = [System.Net.WebExceptionStatus]::Success
    }
    catch [Net.WebException] 
    { 
        $exception_status = $_.Exception.Status
        if ($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError) {
         $resp = [System.Net.HttpWebResponse] $_.Exception.Response
         if (!([int]$resp.StatusCode -eq 308 -Or [int]$resp.StatusCode -eq 200 -Or [int]$resp.StatusCode -eq 201 `
             -Or [int]$resp.StatusCode -eq 403 -Or [int]$resp.StatusCode -eq 401)) {
          Write-Host "got error response from server, status returned $($resp.StatusCode)"
          for($i=0; $i -lt $resp.Headers.Count; $i++) { 
	        Write-Host "\nHeader Name:$($resp.Headers.Keys[$i]), Value :$($resp.Headers[$i])"
          } 
         }
        }  else {
           Write-Host "connection issue: status = $($_.Exception.Status)"               
        } 
    }
  if ($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError -Or $exception_status -eq [System.Net.WebExceptionStatus]::Success) {
   if ([int]$resp.StatusCode -eq 308) {
     @{"httpStatusCode" = $([int]$resp.StatusCode); "Range" = $($resp.Headers['Range'])}
   } elseif ([int]$resp.StatusCode -eq 200 -Or [int]$resp.StatusCode -eq 201) {
     @{"httpStatusCode" = $([int]$resp.StatusCode); "Range" = $($resp.Headers['Range']); "file_metadata" = $respTxt}
   }
   else {
      @{"httpStatusCode" = $([int]$resp.StatusCode)} 
   }
  } else { @{"httpStatusCode" = [int]$exception_status} } 
}

function check-resumable-file-upload-status-req($resumable_location,$file_length) {
    Write-Host "chaking status of resumable upload"
    $enc = [System.Text.Encoding]::GetEncoding("UTF-8")
    Write-Host "url to send = $resumable_location"
    [void]$resp
    [void]$exception_status
    [void]$respTxt
    $wr = [System.Net.HttpWebRequest]::Create($resumable_location)    
    $wr.Proxy = $proxy
  try {
    $wr.Method= 'PUT';
    $wr.Timeout = 10000;
    $wr.ContentType="application/data";
    $wr.Headers.Add("Authorization: Bearer $($script:session_auth_token)")
    $wr.ContentLength = 0
    Write-Host "buf_str=$buf_str; byte_buffer_length=$byte_buffer_length"
    Write-Host "Content-Range: bytes */${file_length}"
    $wr.Headers.Add("Content-Range: bytes */${file_length}")
    $resp = $wr.GetResponse()
    #$resp_stream = $resp.GetResponseStream()
    #$sr = New-Object System.IO.StreamReader($resp_stream)
    #$respTxt = $sr.ReadToEnd()
    #$resp_stream.Close()
    $exception_status = [System.Net.WebExceptionStatus]::Success
    }
    catch [Net.WebException] 
    { 
        $exception_status = $_.Exception.Status
        if ($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError) {
         $resp = [System.Net.HttpWebResponse] $_.Exception.Response
         if (!([int]$resp.StatusCode -eq 308 -Or [int]$resp.StatusCode -eq 200 -Or [int]$resp.StatusCode -eq 201 `
             -Or [int]$resp.StatusCode -eq 403 -Or [int]$resp.StatusCode -eq 401)) {
          Write-Host "got error response from server, status returned $($resp.StatusCode)"
          for($i=0; $i -lt $resp.Headers.Count; $i++) { 
	        Write-Host "\nHeader Name:$($resp.Headers.Keys[$i]), Value :$($resp.Headers[$i])"
          } 
         }
        }  else {
           Write-Host "connection issue: status = $($_.Exception.Status)"               
        } 
    }
  if ($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError -Or $exception_status -eq [System.Net.WebExceptionStatus]::Success) {
   if ([int]$resp.StatusCode -eq 308 -Or [int]$resp.StatusCode -eq 200 -Or [int]$resp.StatusCode -eq 201) {
         @{"httpStatusCode" = $([int]$resp.StatusCode); "Range" = $($resp.Headers['Range'])}
   } else {
      @{"httpStatusCode" = $([int]$resp.StatusCode)} 
   } 
  } else { @{"httpStatusCode" = [int]$exception_status} } 
}

function calculate_backoff_delay($failed_attempts) {
  [int]$maxDelayInSeconds = 1024 
  [int]$delayInSeconds = [math]::round(((1 / 2) * ([math]::pow(2, $failed_attempts) - 1)),0);
  return $(if ($maxDelayInSeconds -lt $delayInSeconds) {$maxDelayInSeconds} else {$delayInSeconds});
}

function upload-file($FilePath, $parent_folder_id, $overwrite, $remote_file_id) {
   $file_descriptor = Get-Item $FilePath

   $fileName = $file_descriptor.Name
   Write-Host "uploading file $($file_descriptor.FullName)"

    
   # Calculate block size in bytes, size must be in multiples of 256 KB (256 x 1024 bytes) otherwise google return 400 response
   $BlockSize = 256 * 1024 * 5
   

   Write-Host "file size = $($file_descriptor.length), block size = $BlockSize"
   Write-Host "[$([System.DateTime]::Now.ToString("dd-MM-yyyy HH:mm:ss"))] Uploading '$($FilePath)' (normal)"
   # Use regular approach.
   $Fs = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
   $br = New-Object System.IO.BinaryReader($Fs)
   $buffer = New-Object System.Byte[]($BlockSize)
   #return $Upload
   $bytesRead
   $first = $True
   $range_start = 0
   $range_end = 0
   $req_loop_attempts = 0
   [void]$status
   [void]$resumable_location
   Write-Progress -Id 1 -Activity "Uploading file $fileName" -Status "StatusString" -PercentComplete 0 -CurrentOperation "Starting the upload"
   if (Test-Path $PSScriptRoot\$resumable_transfer_state_filename -PathType Leaf) {
     Write-Host "found resumable file state file, possible unfinished upload, checking it"
     $resume_file_content = [System.IO.File]::ReadAllText("$PSScriptRoot\$resumable_transfer_state_filename")
     Write-Host = "resume file state content = $resume_file_content"
     $resumable_state = ConvertFrom-Json $resume_file_content 
     Write-Host $resumable_state.filepath
     if ($resumable_state.filepath -And $resumable_state.url -And (Test-Path $resumable_state.filepath -PathType Leaf) -And $resumable_state.filepath -eq $file_descriptor.FullName) {
        $status =  check-resumable-file-upload-status-req $resumable_state.url $file_descriptor.length
        if ($status.httpStatusCode -eq 308 -And $status.Range -And $status.Range -match "bytes=\d+\-(\d+)") {
           [int] $seek_pos = [convert]::ToInt32($Matches[1], 10) + 1 
           Write-Host "uploaded so far $($Matches[1]) bytes, seek to the position $seek_pos in file"
           $br.BaseStream.Seek($seek_pos, [System.IO.SeekOrigin]::Begin)
           $range_start = $seek_pos
           $resumable_location = $resumable_state.url
        } elseif ($status.httpStatusCode -eq 404) {
           Write-Host "resume session has expired, deleting the state file and starting again"
           Remove-Item -Path $PSScriptRoot\$resumable_transfer_state_filename -ErrorAction SilentlyContinue
        } elseif ($status.httpStatusCode -eq 200 -Or $status.httpStatusCode -eq 201) {
           Write-Host "The file was fully uploaded already, no need to repeat the upload, deleting state file and returning from upload call"
           Remove-Item -Path $PSScriptRoot\$resumable_transfer_state_filename -ErrorAction SilentlyContinue
           return
        }
     }
   }

   while (($bytesRead = $br.Read($buffer, 0, $buffer.Length)) -gt 0)
   {
      if ($first -And !$resumable_location) {
         $first = $False
         Write-Host "first chunk"
         if ($file_descriptor.length -lt $BlockSize) {
            Write-Host "file size less then our block size, send as multipart stream in one go"
            $repeat_op = $False
            $req_loop_attempts = 0
            do {
              $status = upload-file-from-bytebuf-in-one-req $parent_folder_id $file_descriptor $buffer $bytesRead $overwrite $remote_file_id
              $repeat_op = !$status['httpStatusCode'] -Or !($status['httpStatusCode'] -eq 200 -Or $status['httpStatusCode'] -eq 201)
              if ($repeat_op) {
                if ($status['httpStatusCode'] -eq 401) {
                  Write-Host "got Unauthenticated error, renewing the token and repeating the request"
                  $script:session_auth_token = Renew-AuthToken
                  continue
                }
                else {
                 $req_loop_attempts++
                 $delay = $(calculate_backoff_delay $req_loop_attempts)
                 Write-Host "error while executing upload file in a single multipart request, code = $($status['httpStatusCode']) repeating the operation in $delay seconds"
                 Write-Progress -Id 1 -Activity "Uploading file $fileName" -Status "StatusString" -PercentComplete 0 -CurrentOperation "Request error, sleeping $delay seconds"
                 Start-Sleep -s $delay
                }
               }
            } while ($repeat_op) 
            break
         } else {
            Write-Host "file size is greater than our block size, initiate resumable upload"
            $repeat_op = $False
            $req_loop_attempts = 0
            do {
              $status = start-resumable-file-upload-req $parent_folder_id $file_descriptor $overwrite $remote_file_id
              $repeat_op = !$status['httpStatusCode'] -Or !$status['resumable_location'] -Or !$status['httpStatusCode'] -eq 200
              if ($repeat_op) {
                if ($status['httpStatusCode'] -eq 401) {
                  Write-Host "got Unauthenticated error, renew the token and repeat the request"
                  $script:session_auth_token = Renew-AuthToken
                  continue
                }
                else {
                 $req_loop_attempts++
                 $delay = $(calculate_backoff_delay $req_loop_attempts)
                 Write-Host "error while initiating large file upload, repeating the operation in $delay seconds"
                 Write-Progress -Id 1 -Activity "Uploading file $fileName" -Status "StatusString" -PercentComplete 0 -CurrentOperation "Upload initialization request error, sleeping $delay seconds"
                 Start-Sleep -s $delay
                }
               }
            } while ($repeat_op)
            $resumable_location = $status['resumable_location'] 
            Write-Host "initialization succesfull, next, we write first block"
            Write-Progress -Id 1 -Activity "Uploading file $fileName" -Status "StatusString" -PercentComplete 0 -CurrentOperation "Upload initialized"
            $range_start = 0
            # TODO process files with zero length
            $range_end = $bytesRead-1            
         }
      } elseif ($first -And $resumable_location) {
          $first = $False
          Write-Host "first entry for seeked offset, setting our range to a special case"
          $range_end = $range_start + $bytesRead-1          
      }
      else {
          $range_start = $range_start + $BlockSize
          $range_end = $range_start + $bytesRead-1          
      }
#      check-resumable-file-upload-status-req $auth_token $resumable_location $FileSize
      $repeat_op = $False
      $req_loop_attempts = 0
      do {
        $status = upload-resumable-file-chunk-req $resumable_location $range_start $range_end $fileName $file_descriptor.length $buffer $bytesRead
        $repeat_op = !$status -Or !$status['httpStatusCode'] -Or !($status['httpStatusCode'] -eq 404 -Or $status['httpStatusCode'] -eq 200 -Or $status['httpStatusCode'] -eq 201 -Or $status['httpStatusCode'] -eq 308)
        if ($repeat_op -And $status['httpStatusCode'] -And !($status['httpStatusCode'] -eq 404 )) {
          if ($status['httpStatusCode'] -eq 401) {
           Write-Host "got Unauthenticated error, renew the token and repeating the request"
           $script:session_auth_token = Renew-AuthToken
           continue
          }
          else {
           $req_loop_attempts++
           $delay = $(calculate_backoff_delay $req_loop_attempts)
           Write-Host "error while uploading large file piece,code = $($status['httpStatusCode']) repeating the operation in $delay seconds"
           Write-Progress -Id 1 -Activity "Uploading file $fileName" -Status "Sleeping" -PercentComplete (($range_end+1)/$file_descriptor.length*100) -CurrentOperation "Request error, sleeping for $delay seconds, then repeat the request" 
           Start-Sleep -s $delay
          }
         }
      } while ($repeat_op)
      if ($status['httpStatusCode'] -And $status['httpStatusCode'] -eq 404) {
         Write-Host "Upload large file session has expired at Google server, have to start from beginning"
         Write-Progress -Id 1 -Activity "Uploading file $fileName" -Status "Working" -PercentComplete 0 -CurrentOperation "Upload large file session has expired, restart the upload"
         Write-Host "Reset the seek pointer at opened file to beginning"
         $first = $True
         $br.BaseStream.Seek(0, [System.IO.SeekOrigin]::Begin) 
         continue        
      }
      Write-Progress -Id 1 -Activity "Uploading file $fileName" -Status "Working" -PercentComplete (($range_end+1)/$file_descriptor.length*100) -CurrentOperation "File portion was uploaded succesfully" 
#      Write-Host "----end loop status = $($status['httpStatusCode'])"
      if ($status['httpStatusCode'] -eq 200 -Or $status['httpStatusCode'] -eq 201) {
          Write-Host "entire file was uploaded, exiting the loop"

          Remove-Item -Path $PSScriptRoot\$resumable_transfer_state_filename -ErrorAction SilentlyContinue

          if ($status['file_metadata']) { 
            Write-Host "uploaded file metadata:`r`n$($status['file_metadata'])"
          } else {
            Write-Host "No file metadata was returned"
          }
          break
      }

   }            
   Write-Progress -Id 1 -Activity "Uploading file $fileName" -Completed -Status "Finished" -PercentComplete 100 -CurrentOperation "Done"
   $Fs.Dispose()
   Write-Host "[$([System.DateTime]::Now.ToString("dd-MM-yyyy HH:mm:ss"))] File upload complete!"
}

function get-files-list($query) {
  Write-Host "get folder id for query = $query"
  $wr = [System.Net.HttpWebRequest]::Create("https://www.googleapis.com/drive/v3/files?fields=nextPageToken,files(id,name,createdTime,modifiedTime,mimeType,md5Checksum)&q="`
                                             +$query+"&orderBy=modifiedTime&pageSize=1000")
  $wr.Proxy = $proxy
  $wr.Method = "GET"
  $wr.ContentType = "application/json"
  $wr.Headers.Add("Authorization: Bearer $($script:session_auth_token)")
  $repeat_op = $False
  $req_loop_attempts = 0
  [void]$folder_id
  [void]$exception_status
  [void]$resp
  do {
  try{
   $resp = $wr.GetResponse()
   $ResponseStream = $resp.GetResponseStream()
   $ReadStream = New-Object System.IO.StreamReader $ResponseStream
   $respTxt=$ReadStream.ReadToEnd()
   $exception_status = [System.Net.WebExceptionStatus]::Success
   Write-Host "result=$respTxt"
  } 
  catch [Net.WebException] 
    {       
            $exception_status = $_.Exception.Status
            if ($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError) {
             $resp = [System.Net.HttpWebResponse] $_.Exception.Response
             Write-Host "resp exception code = $([int]$resp.StatusCode)"
             if (!([int]$resp.StatusCode -eq 403 -Or [int]$resp.StatusCode -eq 401 -Or [int]$resp.StatusCode -eq 400)) {
              for($i=0; $i -lt $resp.Headers.Count; $i++) { 
	        Write-Host "\nHeader Name:$($resp.Headers.Keys[$i]), Value :$($resp.Headers[$i])"
              } 
             }
            }  else {
               Write-Host "connection issue: status = $($_.Exception.Status)"               
            } 
    }
#   Write-Host "loop exception status = $exception_status"
   $repeat_op =  ($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError `
                 -And !([int]$resp.StatusCode -eq 403 -Or [int]$resp.StatusCode -eq 401 -Or [int]$resp.StatusCode -eq 400)) `
                 -Or (!($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError) -And !($exception_status -eq [System.Net.WebExceptionStatus]::Success))
   if ($repeat_op) {
    if ($status['httpStatusCode'] -eq 401) {
      Write-Host "got Unauthenticated error, renewind the token and repeating the request"
      $script:session_auth_token = Renew-AuthToken
      continue
    } else {
     $req_loop_attempts++
     $delay = $(calculate_backoff_delay $req_loop_attempts)
     Write-Host "error while getting folder id, repeating the operation in $delay seconds"
     Start-Sleep -s $delay
    }
   }
   } while ($repeat_op)

   if ($exception_status -eq [System.Net.WebExceptionStatus]::Success) {
     #Write-Host $respTxt  "(?:[^"\\]|\\.)*"
    $filelist = @()               
    [string]$strbuf = "0"
    if ($respTxt -match '(?s)"files"\s*\:\s*\[(.+)\s*\]') {
     #Write-Host "00-$($Matches[1])-00"
     $Matches[1] | Select-String '(?s)\{.+?\}\s*,?' -AllMatches | Foreach {$_.Matches} | Foreach {
       $row = @{}
       $_.Value | Select-String '(?s)"(\w+)"\s*\:\s*"[^"]+"' -AllMatches | Foreach {$_.Matches} | Foreach {
        $r = $_.Value -match '(?s)"(\w+)"\s*\:\s*"((?:[^"\\]|\\.)*)"'
        $row[$Matches[1]] = $Matches[2]
       }
      $filelist = $filelist + $row
     }
     @{"httpStatusCode" = $([int]$resp.StatusCode); "filelist" = $filelist}
    }
    } elseif ($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError) { 
      if ([int]$resp.StatusCode -eq 400) {
        Write-Host "got Bad Format response, probably you have supplied ill formatted file search query"
      } 
      @{"httpStatusCode" = $([int]$resp.StatusCode); "filelist" = @()} 
    }
    else { @{"httpStatusCode" = [int]$exception_status} }
}

function delete-file-by-fileid($fileid) {
  Write-Host "initiating delete for file id = $fileid"
  $wr = [System.Net.HttpWebRequest]::Create("https://www.googleapis.com/drive/v3/files/$fileid")
  $wr.Proxy = $proxy
  $wr.Method = "DELETE"
  $wr.Headers.Add("Authorization: Bearer $($script:session_auth_token)")
  $repeat_op = $False
  $req_loop_attempts = 0
  [void]$exception_status
  [void]$resp
  do {
  try{
   $resp = $wr.GetResponse()
   $exception_status = [System.Net.WebExceptionStatus]::Success
  } 
  catch [Net.WebException] 
    {       
            $exception_status = $_.Exception.Status
            if ($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError) {
             $resp = [System.Net.HttpWebResponse] $_.Exception.Response
             if (!([int]$resp.StatusCode -eq 403 -Or [int]$resp.StatusCode -eq 401 -Or [int]$resp.StatusCode -eq 400)) {
             Write-Host "unhandled exception code = $([int]$resp.StatusCode), dumping HTTP headers for logging"
              for($i=0; $i -lt $resp.Headers.Count; $i++) { 
	        Write-Host "\nHeader Name:$($resp.Headers.Keys[$i]), Value :$($resp.Headers[$i])"
              } 
             }
            }  else {
               Write-Host "connection issue: status = $($_.Exception.Status)"               
            } 
    }
   #Write-Host "loop exception status = $exception_status"
   $repeat_op =  ($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError `
                 -And !([int]$resp.StatusCode -eq 403 -Or [int]$resp.StatusCode -eq 401 -Or [int]$resp.StatusCode -eq 400)) `
                 -Or (!($exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError) -And !($exception_status -eq [System.Net.WebExceptionStatus]::Success))
   if ($repeat_op) {
    if ($status['httpStatusCode'] -eq 401) {
      Write-Host "got Unauthenticated error, renewind the token and repeating the request"
      $script:session_auth_token = Renew-AuthToken
      continue
    } else {
     $req_loop_attempts++
     $delay = $(calculate_backoff_delay $req_loop_attempts)
     Write-Host "error while getting folder id, repeating the operation in $delay seconds"
     Start-Sleep -s $delay
    }
   }
   } while ($repeat_op)

   if ($exception_status -eq [System.Net.WebExceptionStatus]::Success -Or $exception_status -eq [System.Net.WebExceptionStatus]::ProtocolError) {
          @{"httpStatusCode" = $([int]$resp.StatusCode)} 
   }
   else { @{"httpStatusCode" = [int]$exception_status} }
}

function PerformDiffirentialBackup    
{
 
 $fullBackup = Get-ChildItem -Path "$backupOutputPath\backup-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]-full.7z" | select -Last 1 -ExpandProperty FullName
 if (-not ($fullBackup) -or -not (Test-Path $fullBackup -PathType Leaf)) {
    throw "No full backup was found. Must have a full backup before performing a differential."
 }

 $status = get-files-list "name = '$($remote_backup_folder)' and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
 Write-Host "size = $($status.filelist.Length)"
 if ($status.filelist.Length -eq 0) {
  Write-Host "backup folder $remote_backup_folder does not exist, exiting"
  exit 1
 }
 $backup_folder_id = $status.filelist[0].id
 
 $backup_timestamp = "$(get-date -f yyyyMMdd-HHmmss)-diff"
 $diff_backup_outputFile = "$backupOutputPath\backup-$backup_timestamp.7z"
 $diff_backup_LogFile = "$backupOutputPath\backup-$backup_timestamp.log"

 $7zipArgs_diff_backup = @(
    "u";                              
   "$fullBackup";                     
    "-t7z";
    "-mx=7";
    "-xr-@`"`"$excludesFile`"`"";
    "-ir-@`"`"$includesFile`"`"";
    "-u-";                                  
    "-up0q3r2x2y2z0w2!`"`"$diff_backup_outputFile`"`""; 
 )

 Write-Output "Found full backup file: $fullBackup"
 Write-Output "Will create diff backup file: $diff_backup_outputFile"

 & $7zip @7zipArgs_diff_backup | Tee-Object -FilePath $diff_backup_LogFile
 if ($LastExitCode -gt 1) 
 {
    throw "7zip failed with exit code $LastExitCode"
 }

 upload-file $diff_backup_outputFile $backup_folder_id
 upload-file $diff_backup_LogFile $backup_folder_id

}


function PerformFullBackup    
{
 Write-Host "performing the full backup"
 $status = get-files-list "name = '$($remote_backup_folder)' and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
 Write-Host "size = $($status.filelist.Length)"
 if ($status.filelist.Length -eq 0) {
  Write-Host "backup folder $remote_backup_folder does not exist, exiting"
  exit 1
 }
 $backup_folder_id = $status.filelist[0].id
 Write-Host "backup folder id = $backup_folder_id"
 $backup_timestamp = "$(get-date -f yyyyMMdd-HHmmss)-full"
 $full_backup_filename = "$backupOutputPath\backup-$backup_timestamp.7z"
 $7zipArgs_full_backup = @(
    "a";                          
    "-t7z";                       
    "-mx=7";                      
    "-xr-@`"`"$excludesFile`"`""; 
    "-ir-@`"`"$includesFile`"`""; 
    "$backupOutputPath\backup-$backup_timestamp.7z"; 
 )
 Write-Host "start 7Zip"
 & $7zip @7zipArgs_full_backup | Tee-Object -FilePath "$backupOutputPath\backup-$backup_timestamp.log"
 if ($LastExitCode -gt 1) 
 {
    throw "7zip failed with exit code $LastExitCode"
 }
 Write-Host "Done, uploading the file"

 upload-file $full_backup_filename $backup_folder_id

 Write-Host "Done, uploading the log"
 upload-file "$backupOutputPath\backup-$backup_timestamp.log" $backup_folder_id

 Write-Host "Done, search for and delete up backup files older than $Days_to_Keep_Backup days"

 # Clean up backup files older than X days
 $allDiffBackups = Get-ChildItem -Path "$backupOutputPath\backup-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]-[a-z][a-z][a-z][a-z].*"
 $mts = (get-date).AddDays(-$Days_to_Keep_Backup).ToString("yyyyMMdd");
 if ($allDiffBackups -is [array] ) {
    $allDiffBackups | % {
        $fts = $_.Name.Substring(7,8);        
        if ($fts -lt $mts) { 
          Write-Host "Deleting old backup at google drive. File: $($_.FullName)"
          $status = get-files-list "name = '$($_.Name)' and '$backup_folder_id' in parents and trashed = false"
          if ($status.filelist.Length -gt 0) {
              delete-file-by-fileid $status.filelist[0].id
          }  
          Write-Host "Deleting local copy of old backup. File: $($_.FullName)"          
          Remove-Item -Path $_.FullName -ErrorAction SilentlyContinue
          Remove-Item -Path "$($_.FullName).log" -ErrorAction SilentlyContinue          
        } 
    } 
 } 
}

function md5filehash($filepath) {
 $md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
 $hash_byte = $md5.ComputeHash([System.IO.File]::ReadAllBytes($filepath))
 $hash = ""
 for ([int]$i = 0; $i -lt $hash_byte.Length; $i++)
        {
            $hash += $hash_byte[$i].ToString("x2");
        }
  $hash
}

function sync-local-folder-to-remote-folder($local_folder,$remote_folder) {
 $status = get-files-list "name = '$($remote_folder)' and mimeType = 'application/vnd.google-apps.folder'"
 $remote_folder_id = ""
 if ($status['httpStatusCode'] -eq 200 -And $status.filelist.Length -gt 0 ) {
   Write-Host "folder id = $($status.filelist[0].id)"
   $remote_folder_id = $status.filelist[0].id 
 } else {
   Write-Host "remote folder not found,exiting"
   exit 1
 }

 $flist_to_upload = Get-ChildItem -Path "$local_folder\*.*"      
 if ($flist_to_upload.Length) {
    $flist_to_upload | % {
          Write-Host "processing file: $($_.FullName)"
          $status = get-files-list "name = '$($_.Name)' and '$remote_folder_id' in parents  and trashed = false"
          if ($status.filelist.Length -gt 0) {
              $hash_str = md5filehash $_.FullName
                Write-Host "file exists on gdrive,remote id = $($status.filelist[0].id) remote name = $($status.filelist[0].name) md checksums: local file = $hash_str, remote file = $($status.filelist[0].md5Checksum)" 
                 if ($status.filelist[0].md5Checksum -eq $hash_str) {
                   Write-Host "MD5 hashes of local and remote files are equal, skipping the update"
                 } else {
                   Write-Host "local and remote file names are identical,but MD5 hashes are diffirent, updating the remote file with new one"
                   #delete-file-by-fileid $status.filelist[0].id
                   upload-file $_.FullName $remote_folder_id $true $status.filelist[0].id
                 }
          } else {
            Write-Host "File does not exists in remote folder, uploading"
            upload-file $_.FullName $remote_folder_id $false
          }   
    } 
 } else { "not array, nothing to sync"} 

}

function pipeline-upload-filelist-to-remote-folder {
 Param (
   [parameter( Mandatory = $true, HelpMessage="folder name, present in google drive" )]
   [string]$folder_name,
   [parameter( Mandatory = $true, ValueFromPipeline = $true, HelpMessage="One or more files to publish" )]
   [System.IO.FileInfo[]]$FileNames
 )
Begin {
 Write-Host "fd = $folder_name"
 $status = get-folder-id $folder_name
 if ($status['httpStatusCode'] -eq 200 -And $status['folder_id']) {
   Write-Host "folder id = $($status['folder_id'])"
 } else {
   Write-Host "backup folder not found,exiting"
   exit 1
 }
}
 Process { 
   Write-Host "$( get-date -f s ): Uploading file: $_"
   upload-file $_.FullName $status['folder_id']
   Write-Host "$( get-date -f s ): Upload completed" 
 }
}

$MIMEHASH = @{".avi"="video/x-msvideo"; ".crt"="application/x-x509-ca-cert"; ".css"="text/css"; ".der"="application/x-x509-ca-cert"; ".flv"="video/x-flv"; ".gif"="image/gif"; ".htm"="text/html"; ".html"="text/html"; ".ico"="image/x-icon"; ".jar"="application/java-archive"; ".jardiff"="application/x-java-archive-diff"; ".jpeg"="image/jpeg"; ".jpg"="image/jpeg"; ".js"="application/x-javascript"; ".mov"="video/quicktime"; ".mp3"="audio/mpeg"; ".mpeg"="video/mpeg"; ".mpg"="video/mpeg"; ".pdf"="application/pdf"; ".pem"="application/x-x509-ca-cert"; ".pl"="application/x-perl"; ".png"="image/png"; ".rss"="text/xml"; ".shtml"="text/html"; ".swf"="application/x-shockwave-flash"; ".txt"="text/plain"; ".log"="text/plain"; ".war"="application/java-archive"; ".wmv"="video/x-ms-wmv"; ".xml"="text/xml"}

function urlencode-params-hash($params_hash) {
 [string]$url_string = ""
 $param_hash = @{}
 foreach($entry in $params_hash.GetEnumerator()) {
   if ($url_string.Length -gt 0) { $url_string += "&" }
   $url_string += $entry.Name + "=" + [URI]::EscapeDataString([string]$entry.Value)
 }
 return $url_string 
}

function Renew-AuthToken {
 $status = post-urlencoded-req "https://accounts.google.com/o/oauth2/token"  `
           @{"client_id" = $script:csecret.web.client_id; "client_secret" = $script:csecret.web.client_secret; "refresh_token" = $script:refresh_token; "grant_type" = "refresh_token"}
    if ($status['httpStatusCode'] -eq 200 -And $status.json -And $status.json.access_token) {
      Write-Host "got renewed access token = $($status.json.access_token)"
      $script:session_auth_token = $status.json.access_token
    } else  {
     Write-Host "FATAL ERROR: failed to renew access token, error code returned = $($status.httpStatusCode) , exiting"
     exit 1
   }
}

function Check-And-Get-Tokens {
 if (Test-Path "$PSScriptRoot\$client_secret_filename" -PathType Leaf) { 
  Write-Host "client secret file present, read values from the file"
  $respTxt = [System.IO.File]::ReadAllText("$PSScriptRoot\$client_secret_filename")

  Write-Host = "csecret contents = $respTxt"
  $script:csecret = ConvertFrom-Json $respTxt 
  Write-Host "csecret.web = $($script:csecret.web.client_id); csecret = $($script:csecret.web.client_secret)" 
  if ([STRING]::IsNullOrEmpty($script:csecret.web.client_id) -Or [STRING]::IsNullOrEmpty($script:csecret.web.client_secret)) { 
   Write-Host "ERROR: wrong format of client secret file named $client_secret_filename, either create or retrieve it again from Google API and place into the script folder";
   exit 1 
  }
 } else { 
  Write-Host "missing client secret file, named $client_secret_filename, retrieve it from Google API site at https://console.developers.google.com and place into the script folder" 
  exit 1
 }

 if (Test-Path $PSScriptRoot\$client_refresh_token_filename -PathType Leaf) { 
  $respTxt = [System.IO.File]::ReadAllText("$PSScriptRoot\$client_refresh_token_filename")
  $rf_obj = ConvertFrom-Json $respTxt
  if ($rf_obj.refresh_token) { 
  Write-Host "refresh token file present, value = $($rf_obj.refresh_token)"
    $script:refresh_token = $rf_obj.refresh_token
    $status = post-urlencoded-req "https://accounts.google.com/o/oauth2/token"  `
           @{"client_id" = $script:csecret.web.client_id; "client_secret" = $script:csecret.web.client_secret; "refresh_token" = $rf_obj.refresh_token; "grant_type" = "refresh_token"}

    if ($status['httpStatusCode'] -eq 200 -And $status.json -And $status.json.access_token) {
      Write-Host "got new access token = $($status.json.access_token)"
      $script:session_auth_token = $status.json.access_token
      return
    } else {
      Write-Host "could not get new access token using client credentials and saved refresh token, http return code = $($status['httpStatusCode']), probably refresh token belongs to another user account or the access to the account has been revoked, will try to retrieve new refresh token"
    }
  }
  else {Write-Host "ERROR: wrong format of refresh token file, delete it and run the script again to repeat authentication process";
   exit 1 
  }
 } else {
  Write-Host "no refresh token present, retrieve it via new auth request"
 }

 $url_query = urlencode-params-hash(@{"scope" = "https://www.googleapis.com/auth/drive"; `
                               "access_type" = "offline"; `
                               "include_granted_scopes" = "true"; `
                               "state" = "state_parameter_passthrough_value"; `
                               "redirect_uri" = $script:csecret.web.redirect_uris[0]; `
                               "response_type" = "code"; `
                               "client_id" = $script:csecret.web.client_id `
                               })

 $browser_url = "https://accounts.google.com/o/oauth2/v2/auth?" + $url_query 
 Write-Host "browser url = $browser_url"
 Write-Host "asking for authorization, starting the browser"
 & rundll32 url.dll,FileProtocolHandler $browser_url
 if ($LastExitCode -gt 1) 
  {
    throw "Browser call failed with exit code  $LastExitCode"
  }
 Write-Host "$(Get-Date -Format s) starting the http listener"

 $http_listener = New-Object System.Net.HttpListener
 $http_listener.Prefixes.Add($binding_url)
 $http_listener.Start()
 $Error.Clear()
 [void]$auth_callback_code
 try
 {
	while ($http_listener.IsListening)
	{
		# analyze incoming request
		$listener_context = $http_listener.GetContext()
		$req = $listener_context.Request
		$resp = $listener_context.Response
                $result = ""
                if ($req.httpMethod -eq "GET" -And $req.Url.LocalPath -eq $oauth_listener_endpoint) {
                        $query_hash = @{}
                        if (![STRING]::IsNullOrEmpty($req.Url.Query)) {
                          foreach ($qp in $req.Url.Query.Substring(1).Split('&')) {
                             $arr1 = $qp.Split("=") 
                             $query_hash[$arr1[0]] = [URI]::UnescapeDataString($arr1[1])
                             $result = $result +" --- " + $arr1[0] +"---" + [URI]::UnescapeDataString($arr1[1])  + "----`r`n"
                          }
                          if ($query_hash.error -eq "access_denied")  {
                            $result = "user denied the access, the script will abot the execution, you may close this window"; 
                          }
                          elseif ($query_hash.code) { $auth_callback_code = $query_hash.code; $result = "access granted, you may close this browser window"  } 
                        } else { $result  = "google auth connectivity problem or error, no GET query available, nothing to do" } 
                        $html_resp = "<html><body><pre>"+$result+"</pre></body></html>"
			# when command is given...			
			$buf = [Text.Encoding]::UTF8.GetBytes($html_resp)
			$resp.ContentLength64 = $buf.Length
			$resp.AddHeader("Last-Modified", [DATETIME]::Now.ToString('r'))
			$resp.AddHeader("Server", "Powershell Gdrive backup webserver/1.0")
			$resp.OutputStream.Write($buf, 0, $buf.Length)
                        $resp.Close()
			Write-Host "$(Get-Date -Format s) Got the code, stopping powershell listener"
                        break

                } else { 			
                       $resp.AddHeader("Server", "Powershell GDrive backup webserver/1.0")
                       $resp.StatusCode = [System.Net.HttpStatusCode]::Forbidden
                       $resp.Close()
                       Write-Host "$(Get-Date -Format s) HTTP $($req.httpMethod) request to $($req.Url.LocalPath) was not recognized, refusing it"                        
                }  

	}
 }
 finally
 {
	# Stop powershell webserver
	$http_listener.Stop()
	$http_listener.Close()
	Write-Host "$(Get-Date -Format s) Powershell webserver stopped."
 }
 if ($auth_callback_code) {
  Write-Host "got our temporary code, exchange it for refresh token and save it"
  $status = post-urlencoded-req "https://www.googleapis.com/oauth2/v4/token" `
            @{"code" = $auth_callback_code; "client_id" = $script:csecret.web.client_id; "client_secret" = $script:csecret.web.client_secret; `
              "redirect_uri" = $script:csecret.web.redirect_uris[0]; "grant_type" = "authorization_code"}
  
  if ($status['httpStatusCode'] -eq 200 -And $status.json -And $status.json.access_token) {
   if ($status.json.refresh_token) {
     Write-Host "got refresh token = $($status.json.refresh_token), saving it"
     [System.IO.File]::WriteAllText("$PSScriptRoot\$client_refresh_token_filename","{`"refresh_token`" : `"$($status.json.refresh_token)`"}")
     $script:refresh_token = $status.json.refresh_token
    } else  { Write-Host "no refresh token returned, looks like our access token has not expired yet, continue anyway" }
    Write-Host "our new access token = $($status.json.access_token)"    
    $script:session_auth_token = $status.json.access_token   
    return    
  } else {
    Write-Host "fatal error, could not get both refresh and access tokens, http return code = $($status['httpStatusCode'])"
    exit 1
  }
 } else { Write-Host "got no user access to the google Drive due to missing access callback code, closing the app"; exit 0 }
}


#----------------------main part ----------------------------
if (!(Test-Path $7zip -PathType Leaf)) {
 Write-Host "7zip standalone console version is required for this script, download it at https://www.7-zip.org/ and place into the script folder"
}
 

#Write-Host "`$args.Length -eq 0 = $($args.Length -eq 0)"
if ($args.Length -eq 0 -Or !($args[0] -eq "full" -Or $args[0] -eq "diff" -Or $args[0] -eq "sync")) { 
Write-Host "Possible script parameters: full for fullbackup, diff for differential backup, sync [local folder full path] [remote gdrive folder]"; exit 0; }

Check-And-Get-Tokens

if ($script:session_auth_token) {
  Write-Host "our access token = $($script:session_auth_token)"  
} else {
  Write-Host "could not get access token, exiting"
  exit 1
}

if ($args[0] -eq "full") { PerformFullBackup }
elseif ($args[0] -eq "diff") { PerformDiffirentialBackup }
elseif ($args[0] -eq "sync" -And $args[1] -And $args[2]) {
sync-local-folder-to-remote-folder $args[1] $args[2]
} 