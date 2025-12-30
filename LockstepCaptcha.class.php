<?php

/**
 * LockstepCaptcha
 *
 * A self-hosted, double-challenge CAPTCHA for PHP that verifies human presence
 * through coordinated cognitive and visual interaction.
 *
 * The challenge operates in lockstep:
 *  1) Text-based reasoning (masked character recognition)
 *  2) Visual interaction (clicking the least frequent icon)
 *
 * Designed to increase the cost of automation while keeping UX simple
 * and avoiding third-party services or invasive tracking.
 *
 * JavaScript is NOT required for correctness or security.
 *
 * @package   LockstepCaptcha
 * @author    Salvatore Fresta
 * @version   1.0.0
 * @license   GNU General Public License v3.0
 * @link      https://www.gnu.org/licenses/gpl-3.0.html
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 */

class LockstepCaptcha {

	private $QUESTION_H          = null;
	private $CANVAS_W            = null;
	private $CANVAS_H            = null;
	private $ICON_JITTER_PAD     = null;
	private $ICON_MAX_TRIES      = null;
	private $ROTATE_MIN_DEG      = null;
	private $ROTATE_MAX_DEG      = null;
	private $CAPTCHA_TTL_SECONDS = null; 
	private $MIN_FILL_SECONDS    = null;
	private $RATE_MAX_TRIES      = null; 
	private $RATE_WINDOW_SECONDS = null;
	private $ICON_DIR            = null; 
	private $ICON_SIZE           = null; 
	private $SECRET_KEY          = null;
	private $ICONS_DISTRIBUTION  = null;
	private $QUESTION_CHARS_NUM  = null;

	public function __construct($config=[]) {
		
		if( session_status() !== PHP_SESSION_ACTIVE ) session_start();

		$this->QUESTION_H          = $config["QUESTION_H"] ?? 50;
		$this->CANVAS_W            = $config["CANVAS_W"] ?? 860;
		$this->CANVAS_H            = $config["CANVAS_H"] ?? 250;
		$this->ICON_JITTER_PAD     = $config["ICON_JITTER_PAD"] ?? 10;
		$this->ICON_MAX_TRIES      = $config["ICON_MAX_TRIES"] ?? 250;
		$this->ROTATE_MIN_DEG      = $config["ROTATE_MIN_DEG"] ?? -50;
		$this->ROTATE_MAX_DEG      = $config["ROTATE_MAX_DEG"] ?? 50;
		$this->CAPTCHA_TTL_SECONDS = $config["CAPTCHA_TTL_SECONDS"] ?? 120;
		$this->MIN_FILL_SECONDS    = $config["MIN_FILL_SECONDS"] ?? 2;
		$this->RATE_MAX_TRIES      = $config["RATE_MAX_TRIES"] ?? 12;
		$this->RATE_WINDOW_SECONDS = $config["RATE_WINDOW_SECONDS"] ?? 300;
		$this->ICON_DIR            = $config["ICON_DIR"] ?? __DIR__ . '/captcha_icons';
		$this->ICON_SIZE           = $config["ICON_SIZE"] ?? 45;
		$this->SECRET_KEY          = $config["SECRET_KEY"] ?? '9f3c7a1d4b8e2a6f0c5d91e7b24a8c3f6e0b7d5a9c4f1e2b8a6d3c0f59e71a';
		$this->ICONS_DISTRIBUTION  = $config["ICONS_DISTRIBUTION"] ?? [7, 5, 2, 1];
		$this->QUESTION_CHARS_NUM  = $config["QUESTION_CHARS_NUM"] ?? rand(3, 5);
		
		if( (int) $this->QUESTION_CHARS_NUM <= 0 ) $this->QUESTION_CHARS_NUM = 3;
		if( empty($this->ICONS_DISTRIBUTION) ) $this->ICONS_DISTRIBUTION = [7, 5, 2, 1];
		if( (int) $this->ICON_SIZE <= 0 ) $this->ICON_SIZE = 45;

	}

	private function hmac(string $data): string {
		return hash_hmac('sha256', $data, $this->SECRET_KEY);
	}

	private function ct_equals(string $a, string $b): bool {
		
		if (function_exists('hash_equals')) return hash_equals($a, $b);
		if (strlen($a) !== strlen($b)) return false;
		$res = 0;
		for ($i=0; $i<strlen($a); $i++) $res |= ord($a[$i]) ^ ord($b[$i]);
		return $res === 0;
		
	}

	private function now(): int { return time(); }

	private function rate_limit_check(): bool {
		
		$t = $this->now();
		$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
		$key = hash('sha256', $ip . '|' . session_id());

		$dir = sys_get_temp_dir() . '/captcha_rl';
		if (!is_dir($dir)) @mkdir($dir, 0700, true);

		$file = $dir . '/' . $key . '.json';

		$data = ['hits' => []];

		if (is_file($file)) {
			$raw = @file_get_contents($file);
			$tmp = json_decode($raw ?: '', true);
			if (is_array($tmp) && isset($tmp['hits']) && is_array($tmp['hits'])) $data = $tmp;
		}

		// keep only window
		$data['hits'] = array_values(array_filter($data['hits'], fn($x) => ($t - (int)$x) <= $this->RATE_WINDOW_SECONDS));

		if (count($data['hits']) >= $this->RATE_MAX_TRIES) {
			@file_put_contents($file, json_encode($data), LOCK_EX);
			return false;
		}

		$data['hits'][] = $t;
		@file_put_contents($file, json_encode($data), LOCK_EX);
		return true;
		
	}

	private function load_icon_paths(): array {
		
		if (!is_dir($this->ICON_DIR)) return [];
		$paths = glob($this->ICON_DIR . '/*.png');
		$paths = array_values(array_filter($paths, fn($p) => is_file($p) && is_readable($p)));
		return $paths;
		
	}

	public function generate_captcha(): array {
		
		$icons = $this->load_icon_paths();
		$combo = $this->make_combined_captcha($icons);

		$token = bin2hex(random_bytes(16));
		$created = $this->now();

		$missingNorm = strtolower(trim($combo['missing']));
		$p1_hash = $this->hmac("p1|{$missingNorm}|{$token}");

		$boxesJson = json_encode($combo['target_boxes'], JSON_UNESCAPED_SLASHES);
		$p2_hash = $this->hmac("p2|{$boxesJson}|{$token}");
		
		if (empty($_SESSION['captcha_csrf']))
    		$_SESSION['captcha_csrf'] = bin2hex(random_bytes(16));
		
		if (session_status() === PHP_SESSION_ACTIVE)
			session_regenerate_id(true);

		$_SESSION['captcha'] = [
			'token'    => $token,
			'created'  => $created,
			'expires'  => $created + $this->CAPTCHA_TTL_SECONDS,
			'p1_hash'  => $p1_hash,
			'p2_hash'  => $p2_hash,
			'boxes'    => $combo['target_boxes'],
			'issued_at'=> $created,
			'ua_hash'  => $this->hmac('ua|' . ($_SERVER['HTTP_USER_AGENT'] ?? '')),
		];

		return [
			'img_b64'  => $combo['img_b64'],   // UNA SOLA IMMAGINE
			'token'    => $token,
			'expires'  => $_SESSION['captcha']['expires'],
		];

	}

	public function validate_captcha(&$error_msg=""): bool {
		
		$csrf = $_POST['captcha_csrf_token'] ?? '';
		
		if (!is_string($csrf) || empty($_SESSION['captcha_csrf']) || !$this->ct_equals($_SESSION['captcha_csrf'], $csrf)) {
			unset($_SESSION['captcha']);
			$error_msg = "Invalid request.";
			return false;
		}
		
		if (!$this->rate_limit_check()) {
		    $error_msg = "Too many attempts. Try again later.";
		    return false;
		}

		if (!isset($_SESSION['captcha'])) {
		    $error_msg = "Captcha missing or expired.";
		    return false;
		}

		$cap = $_SESSION['captcha'];

		// timeout
		if ($this->now() > (int)$cap['expires']) {
		    unset($_SESSION['captcha']);
		    $error_msg = "Captcha expired.";
		    return false;
		}

		// anti-replay: token hidden deve combaciare
		$token = $_POST['captcha_token'] ?? '';
		if (!is_string($token) || $token === '' || !$this->ct_equals($cap['token'], $token)) {
		    unset($_SESSION['captcha']);
		    $error_msg = "Invalid token.";
		    return false;
		}

		// UA binding “soft” (se cambia troppo spesso, sospetto)
		$uaNow = $this->hmac('ua|' . ($_SERVER['HTTP_USER_AGENT'] ?? ''));
		if (!$this->ct_equals($cap['ua_hash'], $uaNow)) {
		    unset($_SESSION['captcha']);
		    $error_msg = "Session changed. Try again.";
		    return false;
		}

		// honeypot
		if (!empty($_POST['captcha_company'])) { // campo che dovrebbe restare vuoto
		    unset($_SESSION['captcha']);
		    $error_msg = "Verification failed.";
		    return false;
		}

		// min-time-to-fill
		$t0 = (int)($cap['issued_at'] ?? 0);
		if ($t0 > 0 && ($this->now() - $t0) < $this->MIN_FILL_SECONDS) {
		    // non blocco “hard” sempre, ma qui facciamo hard per semplicità:
		    unset($_SESSION['captcha']);
		    $error_msg = "Sending too fast. Try again.";
		    return false;
		}

		// Parte 2: coordinate click
		// input name="figure" => figure_x e figure_y
		$x = $_POST['captcha_figure_x'] ?? null;
		$y = $_POST['captcha_figure_y'] ?? null;
		if ($x === null || $y === null || !is_numeric($x) || !is_numeric($y)) {
		    unset($_SESSION['captcha']);
		    $error_msg = "Click not detected.";
		    return false;
		}
		$x = (int)$x;
		$y = (int)$y;

		// Verifica click in uno qualunque dei box target
		$boxes = $cap['boxes'] ?? [];
		$hit = false;
		foreach ($boxes as $b) {
		    if ($x >= $b['x1'] && $x <= $b['x2'] && $y >= $b['y1'] && $y <= $b['y2']) {
		        $hit = true;
		        break;
		    }
		}

		// Firma coerente (anti-tamper)
		$boxesJson = json_encode($boxes, JSON_UNESCAPED_SLASHES);
		$p2_hash_now = $this->hmac("p2|{$boxesJson}|{$token}");
		if (!$this->ct_equals($cap['p2_hash'], $p2_hash_now)) {
		    unset($_SESSION['captcha']);
		    $error_msg = "Invalid verification.";
		    return false;
		}

		if (!$hit) {
		    unset($_SESSION['captcha']);
		    $error_msg = "You clicked the wrong icon.";
		    return false;
		}
		
		
		// Parte 1: verifica stringa
		$code = $_POST['captcha_code'] ?? '';
		if (!is_string($code)) $code = '';
		$codeNorm = strtolower(trim($code));
		$p1_hash_now = $this->hmac("p1|{$codeNorm}|{$token}");
		if (!$this->ct_equals($cap['p1_hash'], $p1_hash_now)) {
		    unset($_SESSION['captcha']);
		    $error_msg = "Wrong code.";
		    return false;
		}

		// one-time success: invalida
		unset($_SESSION['captcha']);
		return true;
		
	}

	private function make_question_data($hosts=[]): array {
				
		if( empty($hosts) ) $hosts[] = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? '';
		
		$full = $hosts[random_int(0, count($hosts)-1)];

		$len = strlen($full);
		$tries = 0;
		do {
		    $start = random_int(0, max(0, $len - $this->QUESTION_CHARS_NUM));
		    $chunk = substr($full, $start, $this->QUESTION_CHARS_NUM);
		    $tries++;
		} while ($tries < 50 && preg_match('/[\.\/]/', $chunk));

		$missing = substr($full, $start, $this->QUESTION_CHARS_NUM);
		$masked  = substr($full, 0, $start);
		
		for($i=0; $i<$this->QUESTION_CHARS_NUM; $i++) $masked .= '*';
		
		$masked  .= substr($full, $start + $this->QUESTION_CHARS_NUM);

		return [
		    'full'    => $full,
		    'masked'  => $masked,
		    'missing' => $missing,
		    'start'   => $start,
		];
	}

	private function draw_random_background($im, int $w, int $h): void {
		// base soft random
		$base = imagecolorallocate($im, random_int(230, 250), random_int(230, 250), random_int(230, 250));
		imagefilledrectangle($im, 0, 0, $w, $h, $base);

		// finto gradiente (strisce orizzontali)
		for ($y = 0; $y < $h; $y += 2) {
		    $c = imagecolorallocatealpha(
		        $im,
		        random_int(200, 245),
		        random_int(200, 245),
		        random_int(200, 245),
		        random_int(80, 110)
		    );
		    imageline($im, 0, $y, $w, $y, $c);
		}

		// macchie/ellissi semi-trasparenti
		for ($i = 0; $i < 25; $i++) {
		    $c = imagecolorallocatealpha(
		        $im,
		        random_int(120, 220),
		        random_int(120, 220),
		        random_int(120, 220),
		        random_int(90, 120)
		    );
		    $cx = random_int(-50, $w + 50);
		    $cy = random_int(-50, $h + 50);
		    $rx = random_int(80, 220);
		    $ry = random_int(40, 180);
		    imagefilledellipse($im, $cx, $cy, $rx, $ry, $c);
		}

		// linee “curve” simulate con segmenti
		for ($i = 0; $i < 16; $i++) {
		    $c = imagecolorallocatealpha(
		        $im,
		        random_int(80, 200),
		        random_int(80, 200),
		        random_int(80, 200),
		        random_int(85, 115)
		    );
		    $x = random_int(0, $w);
		    $y = random_int(0, $h);
		    for ($k = 0; $k < 18; $k++) {
		        $nx = $x + random_int(-60, 60);
		        $ny = $y + random_int(-40, 40);
		        imageline($im, $x, $y, $nx, $ny, $c);
		        $x = $nx; $y = $ny;
		    }
		}

		// noise puntinato
		for ($i = 0; $i < 3500; $i++) {
		    $c = imagecolorallocatealpha(
		        $im,
		        random_int(40, 220),
		        random_int(40, 220),
		        random_int(40, 220),
		        random_int(90, 125)
		    );
		    imagesetpixel($im, random_int(0, $w-1), random_int(0, $h-1), $c);
		}
	}

	private function rects_overlap(array $a, array $b, int $pad = 0): bool {
		return !(
		    $a['x2'] + $pad < $b['x1'] ||
		    $a['x1'] - $pad > $b['x2'] ||
		    $a['y2'] + $pad < $b['y1'] ||
		    $a['y1'] - $pad > $b['y2']
		);
	}

	private function make_icon_stamp($srcPng, int $size, int $angleDeg) {
		// ridimensiona a quadrato $size
		$sw = imagesx($srcPng); $sh = imagesy($srcPng);
		$tmp = imagecreatetruecolor($size, $size);
		imagealphablending($tmp, false);
		imagesavealpha($tmp, true);
		$tr = imagecolorallocatealpha($tmp, 0, 0, 0, 127);
		imagefilledrectangle($tmp, 0, 0, $size, $size, $tr);
		imagecopyresampled($tmp, $srcPng, 0, 0, 0, 0, $size, $size, $sw, $sh);

		// ruota mantenendo trasparenza
		$bg = imagecolorallocatealpha($tmp, 0, 0, 0, 127);
		$rot = imagerotate($tmp, $angleDeg, $bg);
		imagedestroy($tmp);

		imagealphablending($rot, true);
		imagesavealpha($rot, true);

		return $rot; // risorsa GD
	}

	private function make_combined_captcha(array $iconPaths): array {
		
		$num_icons = count($this->ICONS_DISTRIBUTION);
		
		$q = $this->make_question_data();

		if (count($iconPaths) < $num_icons) {
		    // se vuoi: puoi fare un fallback “forme” anche qui, ma per brevità
		    // riuso il tuo fallback e poi “incollerei” sopra la domanda.
		    // Qui facciamo fallback diretto alle forme scatterate (implementazione rapida).
		    return $this->make_combined_shapes_fallback($q);
		}

		// scegli 3 tipi
		shuffle($iconPaths);
		$types = array_slice($iconPaths, 0, $num_icons);

		// distribuzione 7/5/3
		//$counts = [7, 5, 2, 1];
		shuffle($this->ICONS_DISTRIBUTION);
		
		$typeCounts = [];
		for($i=0; $i<$num_icons; $i++)
			$typeCounts[] = $this->ICONS_DISTRIBUTION[$i];
		
		//$typeCounts = [0=>$counts[0], 1=>$counts[1], 2=>$counts[2]];

		$pieces = [];
		foreach ($typeCounts as $ti => $cnt) {
		    for ($i=0; $i<$cnt; $i++) $pieces[] = $ti;
		}
		shuffle($pieces);

		$w = $this->CANVAS_W;
		$h = $this->CANVAS_H;

		$im = imagecreatetruecolor($w, $h);
		imagealphablending($im, true);
		imagesavealpha($im, true);

		// background random rumoroso
		$this->draw_random_background($im, $w, $h);

		// fascia domanda (overlay semi-trasparente)
		$bar = imagecolorallocatealpha($im, 255, 255, 255, 50);
		imagefilledrectangle($im, 0, 0, $w, $this->QUESTION_H, $bar);

		// titolo domanda
		$txt = imagecolorallocate($im, 25, 25, 25);
		imagestring($im, 5, 14, 20, $q['masked'], $txt);

		// area icone (sotto)
		$areaX1 = 18;
		$areaY1 = $this->QUESTION_H + 18;
		$areaX2 = $w - 18;
		$areaY2 = $h - 18;

		// carica immagini tipo
		$typeImgs = [];
		foreach ($types as $p) {
		    $tmp = @imagecreatefrompng($p);
		    if (!$tmp) {
		        imagedestroy($im);
		        return $this->make_combined_shapes_fallback($q);
		    }
		    $typeImgs[] = $tmp;
		}

		// tipo target (meno frequente)
		$minCount = min($typeCounts);
		$targetType = array_search($minCount, $typeCounts, true);

		$placedRects = [];  // tutte le icone
		$targetBoxes = [];  // solo quelle da cliccare

		foreach ($pieces as $ti) {
		    $placed = false;

		    for ($try = 0; $try < $this->ICON_MAX_TRIES; $try++) {
		        $angle = random_int($this->ROTATE_MIN_DEG, $this->ROTATE_MAX_DEG);

		        $stamp = $this->make_icon_stamp($typeImgs[$ti], $this->ICON_SIZE, $angle);
		        $bw = imagesx($stamp);
		        $bh = imagesy($stamp);

		        // se la rotazione rende l'icona troppo grande per l'area, riprova
		        if ($bw > ($areaX2 - $areaX1) || $bh > ($areaY2 - $areaY1)) {
		            imagedestroy($stamp);
		            continue;
		        }

		        $x = random_int($areaX1, $areaX2 - $bw);
		        $y = random_int($areaY1, $areaY2 - $bh);

		        $rect = ['x1'=>$x, 'y1'=>$y, 'x2'=>$x+$bw-1, 'y2'=>$y+$bh-1];

		        $ok = true;
		        foreach ($placedRects as $r) {
		            if ($this->rects_overlap($rect, $r, $this->ICON_JITTER_PAD)) { $ok = false; break; }
		        }

		        if ($ok) {
		            imagecopy($im, $stamp, $x, $y, 0, 0, $bw, $bh);
		            $placedRects[] = $rect;

		            if ($ti === $targetType) {
		                // box cliccabile = bounding box attuale (già include rotazione)
		                $targetBoxes[] = $rect;
		            }

		            $placed = true;
		            imagedestroy($stamp);
		            break;
		        }

		        imagedestroy($stamp);
		    }

		    // se non riesce a piazzarla (molto raro con canvas grande), ignora oppure fallback:
		    if (!$placed) {
		        // in alternativa: potresti ridurre $this->ICON_JITTER_PAD o aumentare $this->CANVAS_H
		    }
		}

		foreach ($typeImgs as $timg) imagedestroy($timg);

		// extra rumore “sopra” (leggero)
		for ($i=0; $i<10; $i++) {
		    $c = imagecolorallocatealpha($im, random_int(80,180), random_int(80,180), random_int(80,180), random_int(85,115));
		    imageline($im, random_int(0,$w-1), random_int(0,$h-1), random_int(0,$w-1), random_int(0,$h-1), $c);
		}

		ob_start();
		imagepng($im);
		$png = ob_get_clean();
		imagedestroy($im);

		return [
		    'img_b64'      => 'data:image/png;base64,' . base64_encode($png),
		    'missing'      => $q['missing'],
		    'masked'       => $q['masked'],
		    'full'         => $q['full'],
		    'target_boxes' => $targetBoxes,
		    'w' => $w, 'h' => $h,
		];
	}

	private function make_combined_shapes_fallback(array $q): array {
		
		$num_icons = count($this->ICONS_DISTRIBUTION);		
		shuffle($this->ICONS_DISTRIBUTION);
		
		$typeCounts = [];
		for($i=0; $i<$num_icons; $i++)
			$typeCounts[] = $this->ICONS_DISTRIBUTION[$i];
		
		$pieces = [];
		foreach ($typeCounts as $ti=>$cnt) for ($i=0;$i<$cnt;$i++) $pieces[] = $ti;
		shuffle($pieces);

		$w = $this->CANVAS_W; $h = $this->CANVAS_H;

		$im = imagecreatetruecolor($w, $h);
		imagealphablending($im, true);
		imagesavealpha($im, true);

		$this->draw_random_background($im, $w, $h);

		$bar = imagecolorallocatealpha($im, 255, 255, 255, 50);
		imagefilledrectangle($im, 0, 0, $w, $this->QUESTION_H, $bar);

		$txt = imagecolorallocate($im, 25, 25, 25);
		$accent = imagecolorallocate($im, 210, 0, 0);
		imagestring($im, 5, 14, 20, "Site: ".$q['masked'], $txt);

		$areaX1 = 18; $areaY1 = $this->QUESTION_H + 18;
		$areaX2 = $w - 18; $areaY2 = $h - 18;

		$minCount = min($typeCounts);
		$targetType = array_search($minCount, $typeCounts, true);

		$placedRects = [];
		$targetBoxes = [];

		foreach ($pieces as $ti) {
		    for ($try=0; $try<$this->ICON_MAX_TRIES; $try++) {
		        $bw = $this->ICON_SIZE;
		        $bh = $this->ICON_SIZE;
		        $x = random_int($areaX1, $areaX2 - $bw);
		        $y = random_int($areaY1, $areaY2 - $bh);
		        $rect = ['x1'=>$x,'y1'=>$y,'x2'=>$x+$bw-1,'y2'=>$y+$bh-1];

		        $ok = true;
		        foreach ($placedRects as $r) {
		            if ($this->rects_overlap($rect, $r, $this->ICON_JITTER_PAD)) { $ok=false; break; }
		        }
		        if (!$ok) continue;

		        $col = imagecolorallocatealpha($im, random_int(20,220), random_int(20,220), random_int(20,220), 30);
		        if ($ti === 0) {
		            imagefilledellipse($im, $x + $bw/2, $y + $bh/2, $bw-6, $bh-6, $col);
		        } elseif ($ti === 1) {
		            imagefilledrectangle($im, $x+4, $y+4, $x+$bw-4, $y+$bh-4, $col);
		        } else {
		            $p = [$x + $bw/2, $y+4, $x+4, $y+$bh-4, $x+$bw-4, $y+$bh-4];
		            imagefilledpolygon($im, $p, 3, $col);
		        }

		        $placedRects[] = $rect;
		        if ($ti === $targetType) $targetBoxes[] = $rect;
		        break;
		    }
		}

		ob_start();
		imagepng($im);
		$png = ob_get_clean();
		imagedestroy($im);

		return [
		    'img_b64'      => 'data:image/png;base64,' . base64_encode($png),
		    'missing'      => $q['missing'],
		    'masked'       => $q['masked'],
		    'full'         => $q['full'],
		    'target_boxes' => $targetBoxes,
		    'w'            => $w,
			'h'            => $h,
		];
		
	}

}

?>
