<?php

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Scripting/PHPClass.php to edit this template
 */

namespace losthost\swanctlServer;
use PHPUnit\Framework\TestCase;

/**
 * Description of ServerTest
 *
 * @author drweb
 */
class ServerTest extends TestCase {
    
    public function testCanUpdateSecrets() {
        $model = \losthost\swanctlModel\Model::getModel();
        $model->connect(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PREFIX);
        
        $server = new Server(VPN_USER, VPN_HOST, VPN_HOST_ID, file_get_contents(PRIVATE_KEY_FILE));
        $server->updateSecrets();
    }
}
