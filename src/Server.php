<?php

namespace losthost\swanctlServer;

/**
 * A view of swanctlModel on a vpn-server created with https://github.com/jawj/IKEv2-setup#vpn-server
 *
 * @author drweb
 */
class Server {
    
    const IPSEC_SECRETS_FILE = '/etc/ipsec.secrets';
    const IPSEC_SECRETS_COMMAND = '/usr/sbin/ipsec secrets';
    
    const SQL_GET_SECRETS = <<<END
                SELECT
                    login, password
                FROM
                    [sctl_connections]
                WHERE
                    is_enabled = 1
                    AND valid_till >= ?
            END;
    
    protected $user;
    protected $host;
    protected $host_id;
    protected $private_key;
    
    public function __construct(string $user, string $host, string $host_id, string $private_key) {
        $this->user = $user;
        $this->host = $host;
        $this->host_id = $host_id;
        $this->private_key = $private_key;
    }
    
    public function updateSecrets() {
        $secrets = $this->getSecrets();
        $this->putSecrets($secrets);
        $this->applySecrets();
    }
    
    protected function getSecrets() {
    
        $secrets = $this->host. ' : RSA "privkey.pem"';
        
        $model = \losthost\swanctlModel\Model::getModel();
        $connections = $model->connection->list('is_enabled = ? AND valid_till > ?', [1, $model->now(true)]);
        
        foreach ($connections as $connection) {
            $secrets .= $connection->asString("\n". '%login% : EAP "%password%"');
        }

        return "$secrets\n";
    }
    
    protected function putSecrets($secrets) {
        $pkey = \phpseclib3\Crypt\PublicKeyLoader::loadPrivateKey($this->private_key);
        
        $sftp = new \phpseclib3\Net\SFTP($this->host);
        $ssh_host_id = $sftp->getServerPublicHostKey();
        if ($this->host_id != $ssh_host_id) {
            throw new \Exception('Invalid host id. Got '. $ssh_host_id);  
        }
        
        if (!$sftp->login($this->user, $pkey)) {
            throw new \Exception('Not authenticated with given key');   
        }
        
        if (!$sftp->put(self::IPSEC_SECRETS_FILE, $secrets)) {
            throw new \Exception('Can not update '. self::IPSEC_SECRETS_FILE);      
        }
    }
    
    protected function applySecrets() {

        $pkey = \phpseclib3\Crypt\PublicKeyLoader::loadPrivateKey($this->private_key);

        $ssh = new \phpseclib3\Net\SSH2($this->host);
        $ssh_host_id = $ssh->getServerPublicHostKey();
        if ($this->host_id != $ssh_host_id) {
            throw new \Exception('Invalid host id. Got '. $ssh_host_id);  
        }
        
        if (!$ssh->login($this->user, $pkey)) {
            throw new \Exception('Not authenticated with given key');   
        }

        $ssh->exec(self::IPSEC_SECRETS_COMMAND);
        if ($ssh->getExitStatus()) {
            throw new \Exception('Can not exec '. self::IPSEC_SECRETS_COMMAND);                 
        }
        
    }
}
