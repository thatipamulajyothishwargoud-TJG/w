$ErrorActionPreference = 'Stop'

$runtimeDirectory = 'C:\Users\thati\hrportal-runtime'
$environmentFile = Join-Path $runtimeDirectory 'local-env.ps1'
$phpExecutable = Join-Path $runtimeDirectory 'php\php.exe'
$routerFile = Join-Path $PSScriptRoot 'tools\router.php'
$mysqlExecutable = 'C:\tools\mysql\current\bin\mysqld.exe'
$mysqlDataDirectory = Join-Path $runtimeDirectory 'mysql-data'

if (-not (Test-Path -LiteralPath $environmentFile)) {
    throw "Local secrets file not found at $environmentFile. Configure the environment variables described in .env.example."
}
if (-not (Test-Path -LiteralPath $phpExecutable)) {
    throw "PHP was not found at $phpExecutable. Install PHP 8.2+ or update this script for your PHP installation."
}

. $environmentFile
$env:APP_URL = 'http://127.0.0.1:8088'
$env:APP_DEMO_MODE = 'true'

$databasePort = if ($env:DB_PORT) { [int]$env:DB_PORT } else { 3306 }
function Test-LocalDatabasePort([int]$Port) {
    $probe = [System.Net.Sockets.TcpClient]::new()
    try {
        $probe.Connect('127.0.0.1', $Port)
        return $true
    } catch {
        return $false
    } finally {
        $probe.Dispose()
    }
}

if (-not (Test-LocalDatabasePort $databasePort)) {
    if (-not (Test-Path -LiteralPath $mysqlExecutable) -or -not (Test-Path -LiteralPath $mysqlDataDirectory)) {
        throw "MySQL is not listening on port $databasePort and its local runtime files are unavailable. Start your configured MySQL server, then run this script again."
    }

    $mysqlErrorLog = Join-Path $runtimeDirectory 'mysql-local.err.log'
    $mysqlOutputLog = Join-Path $runtimeDirectory 'mysql-local.out.log'
    Start-Process -FilePath $mysqlExecutable -ArgumentList "--datadir=$mysqlDataDirectory", "--port=$databasePort", '--bind-address=127.0.0.1', '--mysqlx=0', '--console' -WindowStyle Hidden -RedirectStandardError $mysqlErrorLog -RedirectStandardOutput $mysqlOutputLog | Out-Null

    $databaseReady = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        if (Test-LocalDatabasePort $databasePort) {
            $databaseReady = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $databaseReady) {
        throw "MySQL did not start on port $databasePort. Check $mysqlErrorLog for details."
    }
}

Write-Host "CloudFen is starting at $($env:APP_URL). Keep this window open while using the site."
& $phpExecutable -S 127.0.0.1:8088 -t $PSScriptRoot $routerFile
