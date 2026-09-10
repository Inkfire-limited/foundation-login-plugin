<?php
// Isolated hook/attribute checks. WordPress and credentials are not loaded.
define('ABSPATH', __DIR__);
$actions=[];$filters=[];
function add_action($h,$f,$p=10){global $actions;$actions[$h][] = [$f,$p];}
function add_filter($h,$f,$p=10){global $filters;$filters[$h][] = [$f,$p];}
require dirname(__DIR__).'/inc/ifls-login-script-delivery.php';
$checks=[];
$checks['filters_not_global']=count($filters)===0;
$checks['login_init_registered']=isset($actions['login_init']);
ifls_register_login_script_protection();
$checks['both_hooks_registered']=isset($filters['wp_script_attributes'],$filters['wp_inline_script_attributes']);
$before=['id'=>'example-js','src'=>'/example.js','data-cfasync'=>'true','nonce'=>'test-only-nonce','integrity'=>'sha256-test-only','defer'=>true,'type'=>'module'];
$after=ifls_login_script_attributes($before);
$checks['cf_attribute_first']=array_key_first($after)==='data-cfasync' && $after['data-cfasync']==='false';
$checks['other_attributes_preserved']=array_diff_assoc($before,array_merge($after,['data-cfasync'=>'true']))===[];
$checks['idempotent']=ifls_login_script_attributes($after)===$after;
echo json_encode(['environment'=>'Isolated PHP hook stubs','passed'=>count(array_filter($checks)),'total'=>count($checks),'checks'=>$checks],JSON_PRETTY_PRINT)."\n";
exit(in_array(false,$checks,true)?1:0);
