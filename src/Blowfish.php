<?php
    /* PHP Implementation of Blowfish (www.php-einfach.de)
     *
     * Blowfish was designed in 1993 by Bruce Schneier as a fast,
     * free alternative to existing encryption algorithms.
     *
     * It is a 64-bit Feistel cipher, consisting of 16 rounds.
     * Blowfish has a key length of anywhere from 32 bits up to 448 bits.
     *
     * Blowfish uses a large key-dependent S-boxes, a complex key shedule and a 18-entry P-Box
     *
     * Blowfish is unpatented and license-free, and is available free for all uses.
     *
     * ***********************
     * Diese Implementierung darf frei verwendet werden, der Author uebernimmt keine
     * Haftung fuer die Richtigkeit, Fehlerfreiheit oder die Funktionsfaehigkeit dieses Scripts.
     * Benutzung auf eigene Gefahr.
     *
     * Ueber einen Link auf www.php-einfach.de wuerden wir uns freuen.
     *
     * ************************
     * Usage:
     * <?php
     * include("blowfish.class.php");
     *
     * $blowfish = new Blowfish("secret Key");
     * $cipher = $blowfish->Encrypt("Hello World"); //Encrypts 'Hello World'
     * $plain = $blowfish->Decrypt($cipher); //Decrypts the cipher text
     *
     * echo $plain;
     * ?>
     */

namespace Blowfish;

include __DIR__ . '/blowfish.box.php';

class Blowfish {

   var $pbox, $sbox0, $sbox1, $sbox2, $sbox3;

	// CBC or ECB Mode
	// normaly, CBC Mode would be the right choice
	var $cbc = 1;

   function Blowfish($key) {
      $this->key_setup($key);
   }

   //Verschluesseln
   function encrypt($text) {
      $n = strlen($text);
      if($n%8 != 0) $lng = ($n+(8-($n%8)));
      else $lng = 0;

      $text = str_pad($text, $lng, ' ');
      $text = $this->_str2long($text);

      //Initialization vector: IV
      if($this->cbc == 1) {
         $cipher[0][0] = time();
         $cipher[0][1] = (double)microtime()*1000000;
      }

      $a = 1;
      for($i = 0; $i<count($text); $i+=2) {
         if($this->cbc == 1) {
            //$text mit letztem Geheimtext XOR Verknuepfen
            //$text is XORed with the previous ciphertext
            $text[$i] ^= $cipher[$a-1][0];
            $text[$i+1] ^= $cipher[$a-1][1];
         }

         $cipher[] = $this->block_encrypt($text[$i],$text[$i+1]);
         $a++;
      }

      $output = "";
      for($i = 0; $i<count($cipher); $i++) {
         $output .= $this->_long2str($cipher[$i][0]);
         $output .= $this->_long2str($cipher[$i][1]);
      }

      return base64_encode($output);
   }




   //Entschluesseln
   function decrypt($text) {
      $plain = array();
      $cipher = $this->_str2long(base64_decode($text));
      $output = '';

      if($this->cbc == 1)
         $i = 2; //Message start at second block
      else
         $i = 0; //Message start at first block

      for($i; $i<count($cipher); $i+=2) {
         $return = $this->block_decrypt($cipher[$i],$cipher[$i+1]);

         //Xor Verknuepfung von $return und Geheimtext aus von den letzten beiden Bloecken
         //XORed $return with the previous ciphertext
         if($this->cbc == 1)
            $plain[] = array($return[0]^$cipher[$i-2],$return[1]^$cipher[$i-1]);
         else          //EBC Mode
            $plain[] = $return;
      }

      $output = "";
      for($i = 0; $i<count($plain); $i++) {
         $output .= $this->_long2str($plain[$i][0]);
         $output .= $this->_long2str($plain[$i][1]);
      }

      return $output;
   }

   //Bereitet den Key zum ver/entschluesseln vor
   function key_setup($key) {
      global $pbox,$sbox0,$sbox1,$sbox2,$sbox3;

      $this->pbox = $pbox;
      $this->sbox0 = $sbox0;
      $this->sbox1 = $sbox1;
      $this->sbox2 = $sbox2;
      $this->sbox3 = $sbox3;



      if(!isset($key) || strlen($key) == 0)
         $key = array(0);
      else if(!is_array($key))
         $key = $this->_str2long(str_pad($key, strlen($key)+strlen($key)%4, $key));

      # XOR Pbox1 with the first 32 bits of the key, XOR P2 with the second 32-bits of the key,
      for($i=0;$i<count($this->pbox);$i++)
         $this->pbox[$i] ^= $key[$i%count($key)];



      $v[0] = 0x00000000;
      $v[1] = 0x00000000;

      //P-Box durch verschluesselte Nullbit Bloecke ersetzen. In der niechsten Runde das Resultat erneut verschluesseln
      //Encrypt Nullbit Blocks and replace the Pbox with the Chiffre. Next round, encrypt the result
      for($i=0;$i<count($pbox);$i+=2) {
         $v = $this->block_encrypt($v[0],$v[1]);
         $this->pbox[$i] = $v[0];
         $this->pbox[$i+1] = $v[1];
      }




      //S-Box [0 bis 3] durch verschloesselte Bloecke ersetzen
      //Replace S-Box [0 to 3] entries with encrypted blocks
      for($i=0;$i<count($sbox0);$i+=2) {
         $v = $this->block_encrypt($v[0],$v[1]);
         $this->sbox0[$i] = $v[0];
         $this->sbox0[$i+1] = $v[1];
      }

      //S-Box1
      for($i=0;$i<count($sbox1);$i+=2) {
         $v = $this->block_encrypt($v[0],$v[1]);
         $this->sbox1[$i] = $v[0];
         $this->sbox1[$i+1] = $v[1];
      }

      //S-Box2
      for($i=0;$i<count($sbox2);$i+=2) {
         $v = $this->block_encrypt($v[0],$v[1]);
         $this->sbox2[$i] = $v[0];
         $this->sbox2[$i+1] = $v[1];
      }

      //S-Box3
      for($i=0;$i<count($sbox3);$i+=2) {
         $v = $this->block_encrypt($v[0],$v[1]);
         $this->sbox3[$i] = $v[0];
         $this->sbox3[$i+1] = $v[1];
      }
   }


	//Performs a benchmark
	function benchmark($length=100000) {
		//1000 Byte String
		$string = str_pad("", $length, "text");


		//Key-Setup
		$start1 = time() + (double)microtime();
		$blowfish = new Blowfish("key");
		$end1 = time() + (double)microtime();

		//Encryption
		$start2 = time() + (double)microtime();
		$blowfish->Encrypt($string);
		$end2 = time() + (double)microtime();


		echo "Keysetup: ".round($end1-$start1,2)." seconds <br>";
		echo "Encrypting ".$length." bytes: ".round($end2-$start2,2)." seconds (".round($length/($end2-$start2),2)." bytes/second)<br>";
		echo "Total: ".round($end2-$start1, 2)." seconds (".round($length/($end2-$start1),2)." bytes/second)";

	}

	//verify the correct implementation of the blowfish algorithm
	function check_implementation() {

		$blowfish = new Blowfish("");
		$vectors = array(
			array(array(0x00000000,0x00000000), array(0x00000000,0x00000000), array(0x4EF99745,0x6198DD78)),
			array(array(0xFFFFFFFF,0xFFFFFFFF), array(0xFFFFFFFF,0xFFFFFFFF), array(0x51866FD5,0xB85ECB8A)),
			array(array(0x01234567,0x89ABCDEF), array(0x11111111,0x11111111), array(0x61F9C380,0x2281B096))
		);

		//Correct implementation?
		$correct = true;
		//Test vectors, see http://www.schneier.com/code/vectors.txt
		foreach($vectors AS $vector) {
      	$key = $vector[0];
			$plain = $vector[1];
			$cipher = $vector[2];

			$blowfish->key_setup($key);
			$return = $blowfish->block_encrypt($vector[1][0],$vector[1][1]);

			if($return[0] != $cipher[0] || $return[1] != $cipher[1])
				$correct = false;
		}

		return $correct;

	}



	/***********************************
			Some internal functions
	 ***********************************/
   function block_encrypt($v0, $v1) {
      if ($v0 < 0)
         $v0 += 4294967296;

      if ($v1 < 0)
         $v1 += 4294967296;



      for ($i = 0; $i < 16; $i++) {
         $temp = $v0 ^ $this->pbox[$i];
         if ($temp < 0)
            $temp += 4294967296;

         $v0 = ((($this->sbox0[($temp >> 24) & 0xFF]
               + $this->sbox1[($temp >> 16) & 0xFF]
               ) ^ $this->sbox2[($temp >> 8) & 0xFF]
               ) + $this->sbox3[$temp & 0xFF]
               ) ^ $v1;

         $v1 = $temp;
      }

      $v1 = $this->_xor($v0, $this->pbox[16]);
      $v0 = $this->_xor($temp, $this->pbox[17]);


      return array($v0, $v1);
   }

   function block_decrypt($v0, $v1) {
        if ($v0 < 0)
            $v0 += 4294967296;

        if ($v1 < 0)
            $v1 += 4294967296;


        for ($i = 17; $i > 1; $i--) {
            $temp = $v0 ^ $this->pbox[$i];
            if ($temp < 0)
                $temp += 4294967296;


            $v0 = ((($this->sbox0[($temp >> 24) & 0xFF]
                     + $this->sbox1[($temp >> 16) & 0xFF]
                    ) ^ $this->sbox2[($temp >> 8) & 0xFF]
                   ) + $this->sbox3[$temp & 0xFF]
                  ) ^ $v1;
            $v1 = $temp;
        }
        $v1 = $this->_xor($v0, $this->pbox[1]);
        $v0 = $this->_xor($temp, $this->pbox[0]);

        return array($v0, $v1);
    }



    function _xor($l, $r)
    {
        $x = (($l < 0) ? (float)($l + 4294967296) : (float)$l)
             ^ (($r < 0) ? (float)($r + 4294967296) : (float)$r);

        return (float)(($x < 0) ? $x + 4294967296 : $x);
    }


   //Einen Text in Longzahlen umwandeln
   //Covert a string into longinteger
   function _str2long($data) {
       $n = strlen($data);
       $tmp = unpack('N*', $data);
       $data_long = array();
       $j = 0;

       foreach ($tmp as $value) $data_long[$j++] = $value;
       return $data_long;
   }

   //Longzahlen in Text umwandeln
   //Convert a longinteger into a string
   function _long2str($l){
       return pack('N', $l);
   }

}

?>