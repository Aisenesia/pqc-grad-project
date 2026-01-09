# LaTeX Compilation Script
# This script compiles main.tex and cleans up intermediate files

# Set LaTeX bin path
$latexBin = "C:\Users\merte\AppData\Local\Programs\MiKTeX\miktex\bin\x64"
$env:PATH = "$latexBin;$env:PATH"

Write-Host "Starting LaTeX compilation..." -ForegroundColor Green

# First pass
Write-Host "`nRunning pdflatex (1st pass)..." -ForegroundColor Cyan
pdflatex -synctex=1 -interaction=nonstopmode main.tex | Out-Null

# Run biber for bibliography
Write-Host "Running biber..." -ForegroundColor Cyan
biber main | Out-Null

# Second pass
Write-Host "Running pdflatex (2nd pass)..." -ForegroundColor Cyan
pdflatex -synctex=1 -interaction=nonstopmode main.tex | Out-Null

# Third pass (final)
Write-Host "Running pdflatex (3rd pass)..." -ForegroundColor Cyan
pdflatex -synctex=1 -interaction=nonstopmode main.tex | Out-Null

# Clean up intermediate files
Write-Host "`nCleaning up intermediate files..." -ForegroundColor Yellow
$intermediateExtensions = @(
    "*.aux", "*.log", "*.out", "*.toc", "*.lof", "*.lot",
    "*.bbl", "*.blg", "*.bcf", "*.run.xml", "*.fls",
    "*.fdb_latexmk", "*.nav", "*.snm",
    "*.vrb", "*.dvi", "*.ps"
)

foreach ($ext in $intermediateExtensions) {
    Remove-Item $ext -ErrorAction SilentlyContinue
}

Write-Host "`nCompilation complete! PDF generated: main.pdf" -ForegroundColor Green
Write-Host "All intermediate files have been removed." -ForegroundColor Green
