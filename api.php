<?php
#
# Sample Socket I/O to CGMiner API
#Grabs and parses some useful data and displays it in simple human-readable format. Also polls from litecoinpool and nicehash to get stats if you so choose!
#

#some definitions
$litecoinpool_api_key = "LiteCoinPool API KEY Goes Here";
$nicehash_address = "NiceHash Address Goes Here";



function getsock($addr, $port)
{
 $socket = null;
 $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
 if ($socket === false || $socket === null)
 {
	$error = socket_strerror(socket_last_error());
	$msg = "socket create(TCP) failed";
	echo "ERR: $msg '$error'\n";
	return null;
 }

 $res = socket_connect($socket, $addr, $port);
 if ($res === false)
 {
	$error = socket_strerror(socket_last_error());
	$msg = "socket connect($addr,$port) failed";
	echo "ERR: $msg '$error'\n";
	socket_close($socket);
	return null;
 }
 return $socket;
}
#
# Slow ...
function readsockline($socket)
{
 $line = '';
 while (true)
 {
	$byte = socket_read($socket, 1);
	if ($byte === false || $byte === '')
		break;
	if ($byte === "\0")
		break;
	$line .= $byte;
 }
 return $line;
}
#
function request($cmd)
{
 $socket = getsock('127.0.0.1', 4028);
 if ($socket != null)
 {
	socket_write($socket, $cmd, strlen($cmd));
	$line = readsockline($socket);
	socket_close($socket);

	if (strlen($line) == 0)
	{
		echo "WARN: '$cmd' returned nothing\n";
		return $line;
	}

	#print "$cmd returned '$line'\n";

	if (substr($line,0,1) == '{')
		return json_decode($line, true);

	$data = array();

	$objs = explode('|', $line);
	foreach ($objs as $obj)
	{
		if (strlen($obj) > 0)
		{
			$items = explode(',', $obj);
			$item = $items[0];
			$id = explode('=', $items[0], 2);
			if (count($id) == 1 or !ctype_digit($id[1]))
				$name = $id[0];
			else
				$name = $id[0].$id[1];

			if (strlen($name) == 0)
				$name = 'null';

			if (isset($data[$name]))
			{
				$num = 1;
				while (isset($data[$name.$num]))
					$num++;
				$name .= $num;
			}

			$counter = 0;
			foreach ($items as $item)
			{
				$id = explode('=', $item, 2);
				if (count($id) == 2)
					$data[$name][$id[0]] = $id[1];
				else
					$data[$name][$counter] = $id[0];

				$counter++;
			}
		}
	}

	return $data;
 }

 return null;
}





# Get CGMINER response to $cmd!

if (isset($argv) and count($argv) > 1)
	try {
 $r = request($argv[1]);
	}
	catch {
		echo "No Response from CGMiner!";
	}
else
	try {
 $r = request('summary');
 $x = request('coin');
 $y = $x['COIN'];
  	}
	catch {
		echo "No Response from CGMiner!";
	}
# Display CGMINER response to $cmd!
$q = $r['SUMMARY'];
echo "<html><pre>";
echo 'Hashrate: '; echo $q['MHS av']; echo ' MH/s';
echo '<br>Blocks Found:'; echo $q['Found Blocks'];
 
 
if ($y['Network Difficulty'] * 65536 < 1000000) {
    // Anything less than a million
    $y_format = number_format($y['Network Difficulty'] * 65536);
} else if ($y['Network Difficulty'] * 65536 < 1000000000) {
    // Anything less than a billion
    $y_format = number_format($y['Network Difficulty'] * 65536 / 1000000, 3) . 'M';
} else {
    // At least a billion
    $y_format = number_format($y['Network Difficulty'] * 65536 / 1000000000, 3) . 'G';
}
echo '<br>Block Size:'; echo $y_format;

if ($q['Best Share'] < 1000000) {
    // Anything less than a million
    $n_format = number_format($q['Best Share']);
} else if ($q['Best Share'] < 1000000000) {
    // Anything less than a billion
    $n_format = number_format($q['Best Share'] / 1000000, 3) . 'M';
} else {
    // At least a billion
    $n_format = number_format($q['Best Share'] / 1000000000, 3) . 'G';
}
echo '<br>Best Share:'; echo $n_format;
echo '<br>Accepted Shares:'; echo $q['Accepted'];
echo '<br>Rejected Shares:'; echo $q['Rejected'];
echo '<br>Hardware Errors:'; echo $q['Hardware Errors'];
echo '<br><br>'; #Formatting



#Get Pool Stats!
try {
$derp = file_get_contents('https://www.litecoinpool.org/api?api_key=' . $litecoinpool_api_key); #Grab your current stats from litecoinpool!
}
catch {
	echo "No response from LiteCoinPool!"
}
$json_string = json_decode($derp, true);
if ($json_string['user']['hash_rate'] < 1000) { # If < 1000 hash activity on LiteCoinPool, Grab from NiceHash API Instead!
	try {
$derp = file_get_contents('https://www.nicehash.com/api?method=stats.provider&addr=' . $nicehash_address); #Grab your current stats from NiceHash!
}
catch {
	echo "No response from NiceHash!"
}
$json_string = json_decode($derp, true);

//print_r($json_string); #Debug Line!


#Display Pool Stats !
echo '<br>NiceHash Hashrate:';
echo number_format($json_string['result']['stats']['0']['accepted_speed'] * 1000, 3) . ' MH/s';
echo '<br>Unpaid Rewards:';
echo $json_string['result']['stats']['0']['balance'] . ' BTC';


}
else {
echo '<br>LiteCoinPool Hashrate:';
echo number_format($json_string['user']['hash_rate'] / 1000, 3) . ' MH/s';
echo '<br>Unpaid Rewards:';
echo $json_string['user']['unpaid_rewards'] . ' LTC';
echo '<br>Expected 24H Output:';
echo $json_string['user']['expected_24h_rewards'];
echo '<br>Blocks Found:';
echo $json_string['user']['blocks_found'];
}



//print_r($json_string['user']); #Debug String!


#get and display lmsensors! Only works if exec(); is enabled, not good in production environment!

try {
$cmd= exec('sensors',$output);
}
catch {
	echo "PHP Exec function disabled!";
}

foreach ($output as $line)
{
	//echo $line;
	echo '<br>';
   // need to find the temperature in:
   // Core 0:       +39.0 C  (crit = +100.0 C)
   if (preg_match('/Core\s+0:\s+\+(\d+).*/',$line,$match))
   {
      //print_r($match);
      print ("cpu_temperature:" . $match[1] . " ");
   }
   if (preg_match('/Core\s+1:\s+\+(\d+).*/',$line,$match))
   {
      //print_r($match);
      print ("cpu_temperature:" . $match[1] . " ");
   }
if (preg_match('/Core\s+2:\s+\+(\d+).*/',$line,$match))
   {
      //print_r($match);
      print ("cpu_temperature:" . $match[1] . " ");
   }
if (preg_match('/Core\s+3:\s+\+(\d+).*/',$line,$match))
   {
      //print_r($match);
      print ("cpu_temperature:" . $match[1] . " ");
   }
   

}


#We want to do exciting things here in the future!

#echo '<form>';

#echo '</form>';
#echo $pid;


echo "</pre></html>";
?>
