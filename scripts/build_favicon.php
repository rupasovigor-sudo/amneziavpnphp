<?php
declare(strict_types=1);

// Render the panel favicon set from the same geometry as public/favicon.svg
// (white shield on the brand violet, matching the sidebar logo) with GD:
// public/favicon.ico (16/32/48, PNG-in-ICO) and public/apple-touch-icon.png.
// Supersampled for antialiasing. Usage: php scripts/build_favicon.php

$root = dirname(__DIR__);
const BRAND = [0x5b, 0x53, 0xd6];

/** Sample a cubic Bezier into points (32-unit design space). */
function cubic(array $p0, array $p1, array $p2, array $p3, int $n = 24): array
{
    $pts = [];
    for ($i = 1; $i <= $n; $i++) {
        $t = $i / $n;
        $u = 1 - $t;
        $pts[] = [
            $u ** 3 * $p0[0] + 3 * $u * $u * $t * $p1[0] + 3 * $u * $t * $t * $p2[0] + $t ** 3 * $p3[0],
            $u ** 3 * $p0[1] + 3 * $u * $u * $t * $p1[1] + 3 * $u * $t * $t * $p2[1] + $t ** 3 * $p3[1],
        ];
    }
    return $pts;
}

// Shield outline: M16 5.5 L25 8.8 V15.4 C25 21 21.2 25.4 16 27 C10.8 25.4 7 21 7 15.4 V8.8 Z
function shield(): array
{
    $pts = [[16, 5.5], [25, 8.8], [25, 15.4]];
    $pts = array_merge($pts, cubic([25, 15.4], [25, 21], [21.2, 25.4], [16, 27]));
    $pts = array_merge($pts, cubic([16, 27], [10.8, 25.4], [7, 21], [7, 15.4]));
    $pts[] = [7, 8.8];
    return $pts;
}

// Left-half shade: M16 9.4 V23.8 C12.7 22.4 10.5 19.2 10.5 15.4 V11.4 Z
function shade(): array
{
    $pts = [[16, 9.4], [16, 23.8]];
    $pts = array_merge($pts, cubic([16, 23.8], [12.7, 22.4], [10.5, 19.2], [10.5, 15.4]));
    $pts[] = [10.5, 11.4];
    return $pts;
}

function render(int $size): GdImage
{
    $ss = 8; // supersampling factor
    $big = $size * $ss;
    $k = $big / 32;
    $img = imagecreatetruecolor($big, $big);
    imagesavealpha($img, true);
    imagealphablending($img, false);
    imagefill($img, 0, 0, imagecolorallocatealpha($img, 0, 0, 0, 127));
    imagealphablending($img, true);

    $brand = imagecolorallocate($img, ...BRAND);
    // Rounded square (rx = 7/32).
    $r = (int) round(7 * $k);
    imagefilledrectangle($img, $r, 0, $big - 1 - $r, $big - 1, $brand);
    imagefilledrectangle($img, 0, $r, $big - 1, $big - 1 - $r, $brand);
    foreach ([[$r, $r], [$big - 1 - $r, $r], [$r, $big - 1 - $r], [$big - 1 - $r, $big - 1 - $r]] as [$cx, $cy]) {
        imagefilledellipse($img, $cx, $cy, 2 * $r, 2 * $r, $brand);
    }

    $flat = static function (array $pts) use ($k): array {
        $out = [];
        foreach ($pts as [$x, $y]) {
            $out[] = (int) round($x * $k);
            $out[] = (int) round($y * $k);
        }
        return $out;
    };
    imagefilledpolygon($img, $flat(shield()), imagecolorallocate($img, 255, 255, 255));
    // fill-opacity .38 of brand over white
    $mix = array_map(static fn($c) => (int) round(255 + (($c - 255) * 0.38)), BRAND);
    imagefilledpolygon($img, $flat(shade()), imagecolorallocate($img, ...$mix));

    $out = imagecreatetruecolor($size, $size);
    imagesavealpha($out, true);
    imagealphablending($out, false);
    imagefill($out, 0, 0, imagecolorallocatealpha($out, 0, 0, 0, 127));
    imagecopyresampled($out, $img, 0, 0, 0, 0, $size, $size, $big, $big);
    imagedestroy($img);
    return $out;
}

function png(GdImage $img): string
{
    ob_start();
    imagepng($img, null, 9);
    return (string) ob_get_clean();
}

// ICO with PNG payloads (supported by every current browser).
$sizes = [16, 32, 48];
$blobs = array_map(static fn($s) => png(render($s)), $sizes);
$ico = pack('vvv', 0, 1, count($sizes));
$offset = 6 + 16 * count($sizes);
foreach ($sizes as $i => $s) {
    $ico .= pack('CCCCvvVV', $s, $s, 0, 0, 1, 32, strlen($blobs[$i]), $offset);
    $offset += strlen($blobs[$i]);
}
$ico .= implode('', $blobs);
foreach (['/public/favicon.ico' => $ico, '/public/apple-touch-icon.png' => png(render(180))] as $rel => $data) {
    if (file_put_contents($root . $rel, $data) === false) {
        fwrite(STDERR, "Cannot write {$rel}\n");
        exit(1);
    }
}
echo "Wrote public/favicon.ico (" . strlen($ico) . " B) and public/apple-touch-icon.png\n";
