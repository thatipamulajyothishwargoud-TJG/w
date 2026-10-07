<?php
// PHP development server router. Never expose config, SQL, private files, or tools.
$path=rawurldecode(parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH)??'/');
if(preg_match('#(^|/)\.|^/(config|tools|tests|vendor|deploy|cron)(/|$)|\.(sql|env|md|ini|log|lock|docx?|json)$#i',$path)||str_contains($path,'..')){http_response_code(404);exit('Not found');}
$root=realpath(__DIR__.'/..');$file=realpath($root.$path);
if($file!==false&&!str_starts_with($file,$root.DIRECTORY_SEPARATOR)&&$file!==$root){http_response_code(404);exit('Not found');}
if($file&&is_file($file))return false;
if($path==='/'){require $root.'/index.php';return true;}
http_response_code(404);echo 'Page not found';
