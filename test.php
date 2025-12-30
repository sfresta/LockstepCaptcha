<?php
declare(strict_types=1);
session_set_cookie_params(['secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
ini_set('session.use_strict_mode', '1');
session_start();

require 'LockstepCaptcha.class.php';

function is_mobile_device(): bool {

	$chMobile = $_SERVER['HTTP_SEC_CH_UA_MOBILE'] ?? null;
	
    if( is_string($chMobile) ) {
        if( strpos($chMobile, '?1') !== false ) return true;
        if( strpos($chMobile, '?0') !== false ) return false;
    }

    $ua = strtolower((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
    $mobileRegex = '/(android|webos|iphone|ipad|ipod|blackberry|bb10|iemobile|opera mini|mobile|silk|kindle)/i';
	
    if( $ua !== '' && preg_match($mobileRegex, $ua) )
        return true;

    $accept = strtolower((string)($_SERVER['HTTP_ACCEPT'] ?? ''));
    if( strpos($accept, 'wap') !== false ) return true;

    return false;
	
}

$captcha_config = [
	'SECRET_KEY'         => '9f3c7a1d4b8e2a6f0c5d91e7b24a8c3f6e0b7d5a9c4f1e2b8a6d3c0f59e71a',
	'ICONS_DISTRIBUTION' => [7,5,2,1],
	'QUESTION_CHARS_NUM' => rand(3, 5),
	'ICON_DIR'           => __DIR__ . '/test_icons'
];

if( is_mobile_device() ) {
	$captcha_config['CANVAS_W']           = 350;
	$captcha_config['ICONS_DISTRIBUTION'] = [7,5,1];
	$captcha_config['ICON_SIZE']          = 25;
}

$captcha_obj = new LockstepCaptcha($captcha_config);
$captcha_error_msg = "";
$valid_captcha = null;

if( $_SERVER['REQUEST_METHOD'] == 'POST' )
    $valid_captcha = $captcha_obj->validate_captcha($captcha_error_msg);

$payload = $captcha_obj->generate_captcha();

?>
<!doctype html>
<html>
<head>
	<meta charset="utf-8">
	<title>PHP CAPTCHA</title>
	<meta name="viewport" content="width=device-width, initial-scale=1">

	<style>
		body {
		    font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
		    background: #f4f5f7;
		}

		.box {
		    max-width: 860px;
		    margin: 0 auto;
		    background: #fff;
		    padding: 22px;
		    border-radius: 16px;
		    box-shadow: 0 8px 28px rgba(0,0,0,.08);
		}

		.row {
		    margin: 16px 0;
		}

		.msg {
		    padding: 12px 14px;
		    border-radius: 12px;
		    margin-bottom: 16px;
		    font-size: 15px;
		}

		.err {
		    background: #ffecec;
		    border: 1px solid #ffb5b5;
		    color: #8a0000;
		}

		.ok {
		    background: #eaffea;
		    border: 1px solid #a8e3a8;
		    color: #0a5d0a;
		}

		label {
		    font-weight: 600;
		    display: block;
		    margin-bottom: 6px;
		}

		input[type="text"] {
		    width: 100%;
		    padding: 12px 14px;
		    font-size: 16px;
		    border-radius: 12px;
		    border: 1px solid #ccc;
			box-sizing: border-box;
		}

		input[type="text"]:focus {
		    outline: none;
		    border-color: #4a74ff;
		}

		.hint {
		    font-size: 14px;
		    color: #444;
		    margin-top: 6px;
		}

		.img {
		    display: block;
		    height: auto;
		    border-radius: 14px;
		    border: 1px solid #ddd;
		    cursor: pointer;
			margin: 0 auto;
		}

		.small {
		    font-size: 13px;
		    color: #666;
		    margin-top: 4px;
		}

		.footer {
		    display: flex;
		    justify-content: space-between;
		    align-items: center;
		    margin-top: 18px;
		}

		.time {
		    font-size: 14px;
		    color: #666;
		}

		button {
		    background: #4a74ff;
		    color: #fff;
		    border: none;
		    padding: 10px 18px;
		    font-size: 15px;
		    border-radius: 12px;
		    cursor: pointer;
		}

		button:hover {
		    background: #3b63e6;
		}
	</style>
	</head>

	<body>

		<div class="box">
			
			<?php if( $valid_captcha === true ): ?>
				<div class="msg ok">Valid Captcha</div>
			<?php else: ?>
			
				<?php if ($captcha_error_msg != ""): ?>
					<div class="msg err"><?= htmlspecialchars($captcha_error_msg, ENT_QUOTES, 'UTF-8'); ?></div>
				<?php endif; ?>
			
				<form method="post" action="">

					<input type="hidden" name="captcha_csrf_token" value="<?= htmlspecialchars($_SESSION['captcha_csrf'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
					<input type="hidden" name="captcha_token" value="<?= htmlspecialchars($payload['token'], ENT_QUOTES, 'UTF-8'); ?>">
					<input type="text" name="captcha_company" tabindex="-1" autocomplete="off" style="position:absolute;left:-9999px;width:1px;height:1px;opacity:0">

					<div class="row">
						<input type="image" name="captcha_figure" class="img" src="<?= $payload['img_b64'] ?>" alt="captcha" draggable="false">
					</div>

					<div class="row">
						<label for="captcha_code">Enter the characters replaced by * and then click on the icon that appears the fewest times.</label>
						<input id="captcha_code" name="captcha_code" type="text" inputmode="text" autocomplete="off" required>
					</div>

				</form>
			
			<?php endif; ?>
			
		</div>

	</body>
</html>
