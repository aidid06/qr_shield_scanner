-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Aug 22, 2026 at 02:16 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `qr_shield_scanner`
--

-- --------------------------------------------------------

--
-- Table structure for table `scan_history`
--

CREATE TABLE `scan_history` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `scanned_url` text NOT NULL,
  `scan_status` varchar(50) NOT NULL,
  `malicious_count` int(11) DEFAULT 0,
  `total_engines` int(11) DEFAULT 0,
  `scanned_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `scan_history`
--

INSERT INTO `scan_history` (`id`, `user_id`, `scanned_url`, `scan_status`, `malicious_count`, `total_engines`, `scanned_at`) VALUES
(9, 6, 'https://scanned.page/VbQxL8', 'Malicious', 2, 92, '2026-08-16 08:01:30'),
(10, 6, 'https://idemia-mobile-id.com/testqr-success', 'Safe', 0, 0, '2026-08-16 08:01:46'),
(11, 1, 'https://idemia-mobile-id.com/testqr-success', 'Safe', 0, 92, '2026-08-16 08:06:36'),
(12, 1, 'https://idemia-mobile-id.com/testqr-success', 'Safe', 0, 92, '2026-08-16 08:08:43'),
(13, 1, 'https://idemia-mobile-id.com/testqr-success', 'Safe', 0, 92, '2026-08-16 08:11:15'),
(14, 1, 'https://scanned.page/VbQxL8', 'Malicious', 2, 92, '2026-08-16 08:11:42'),
(15, 1, 'https://scanned.page/VbQxL8', 'Malicious', 2, 92, '2026-08-16 08:15:17');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `role` varchar(20) DEFAULT 'user'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `email`, `password`, `created_at`, `role`) VALUES
(1, 'Admin', 'admin@gmail.com', '$2y$10$IvfIVMFzGYTNvjZhFyihUu8DreiTTLZ0LCRJ4XljVdc2n0kWtoQTq', '2026-08-03 12:54:10', 'admin'),
(6, 'syakir', 'syakirzainor478@gmail.com', '$2y$10$JhyB08mnLNtNfxA/ahxEfuXIkMWNB7SJw8B./Z4XcK7xCdBY5YdAi', '2026-08-16 08:00:39', 'user');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `scan_history`
--
ALTER TABLE `scan_history`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `scan_history`
--
ALTER TABLE `scan_history`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=16;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `scan_history`
--
ALTER TABLE `scan_history`
  ADD CONSTRAINT `scan_history_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
