<?php

if (! function_exists('css_font_family')) {
    /**
     * Make a font-family setting safe to print inside a <style> block.
     * Only letters, digits, spaces, commas, hyphens and quotes survive.
     */
    function css_font_family(mixed $value, string $fallback = "'Poppins', sans-serif"): string
    {
        $value = is_string($value) ? $value : '';
        if ($value === '' || ! preg_match('/^[A-Za-z0-9 ,\'"\-]{1,200}$/', $value)) {
            return $fallback;
        }

        return $value;
    }
}