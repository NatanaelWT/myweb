<?php
$projects = [
    ['title' => 'Project A', 'description' => 'Contoh deskripsi project A', 'link' => '#'],
    ['title' => 'Project B', 'description' => 'Contoh deskripsi project B', 'link' => '#'],
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Natanael Wijaya Tiono | Portfolio</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <header>
        <h1>Natanael Wijaya Tiono</h1>
        <p>Developer</p>
        <nav>
            <a href="#about">About</a>
            <a href="#projects">Projects</a>
            <a href="#contact">Contact</a>
        </nav>
    </header>
    <section id="about">
        <h2>About</h2>
        <p>Halo, saya Natanael Wijaya Tiono. Ini adalah portofolio saya yang sederhana menggunakan PHP.</p>
    </section>
    <section id="projects">
        <h2>Projects</h2>
        <?php foreach ($projects as $project): ?>
            <div class="project">
                <h3><?= htmlspecialchars($project['title']); ?></h3>
                <p><?= htmlspecialchars($project['description']); ?></p>
                <a href="<?= htmlspecialchars($project['link']); ?>">View Project</a>
            </div>
        <?php endforeach; ?>
    </section>
    <section id="contact">
        <h2>Contact</h2>
        <p>Email: <a href="mailto:natanael@example.com">natanael@example.com</a></p>
    </section>
    <footer>
        <p>&copy; <?php echo date('Y'); ?> Natanael Wijaya Tiono</p>
    </footer>
</body>
</html>
