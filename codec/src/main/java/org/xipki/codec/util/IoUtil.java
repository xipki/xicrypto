// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

/**
 * File utility class.
 *
 * @author Lijun Liao (xipki)
 */
public class IoUtil {

  public static final String USER_HOME = System.getProperty("user.home");

  private IoUtil() {
  }

  public static byte[] read(String fileName) throws IOException {
    return Files.readAllBytes(Paths.get(expandFilepath(fileName)));
  }

  public static byte[] read(File file) throws IOException {
    return read(file.getPath());
  }

  public static void save(String fileName, byte[] encoded) throws IOException {
    save(new File(fileName), encoded);
  }

  public static void saveOmitException(String fileName, byte[] encoded) {
    try {
      save(fileName, encoded);
    } catch (IOException e) {
    }
  }

  public static void save(File file, byte[] content) throws IOException {
    File tmpFile = expandFilepath(file);
    mkdirsParent(tmpFile.toPath());

    try (InputStream is = new ByteArrayInputStream(content)) {
      Files.copy(is, tmpFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
    }
  }

  public static void mkdirsParent(Path path) throws IOException {
    Path parent = path.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
  }

  public static void mkdirs(File dir) throws IOException {
    if (dir.exists()) {
      if (!dir.isDirectory()) {
        throw new IOException("Path " + dir.getPath() + " exists but is not a directory");
      }
    } else {
      if (!dir.mkdirs()) {
        throw new IOException("Could not mkdirs for " + dir.getPath());
      }
    }
  }

  public static void renameTo(File srcFile, File destFile) throws IOException {
    if (!srcFile.renameTo(destFile)) {
      throw new IOException("Could not rename " + srcFile.getPath() + " to " + destFile.getPath());
    }
  }

  public static boolean deleteFile(String path) {
    return deleteFile(new File(path));
  }

  public static boolean deleteFile(File file) {
    file = expandFilepath(file);
    if (file.exists()) {
      return file.delete();
    }
    return true;
  }

  public static void deleteFile0(File file) throws IOException {
    if (!deleteFile(file)) {
      throw new IOException("Could not delete " + file.getPath());
    }
  }

  /**
   * Returns whether the path is absolute: either a unix path starting with '/', or a windows
   * path with drive letter.
   * @param path the path.
   * @return whether the path is absolute.
   */
  public static boolean isAbsolutePath(String path) {
    if (path.startsWith("/")) {
      // unix
      return true;
    }

    int index = path.indexOf(':');
    // windows
    return index == 1 || index == 2;
  }

  /**
   * Replaces the leading '~' by the user home directory.
   * @param path the path.
   * @return the expanded path.
   */
  public static String expandFilepath(String path) {
    if (Args.notBlank(path, "path").startsWith("~")) {
      return USER_HOME + path.substring(1);
    }
    return path;
  }

  public static File expandFilepath(File file) {
    String path = file.getPath();
    String expandedPath = expandFilepath(path);
    return path.equals(expandedPath) ? file : new File(expandedPath);
  }

  // Read last line of the file
  public static String readLastNonBlankLine(File file) throws IOException {
    StringBuilder builder = new StringBuilder();
    try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
      long fileLength = file.length() - 1;
      if (fileLength < 1) {
        return "";
      }

      // Set the pointer at the last of the file
      raf.seek(fileLength);
      long pointer = fileLength;

      while (true) {
        while (pointer >= 0) {
          raf.seek(pointer--);

          char c;
          // read from the last one char at the time
          c = (char) raf.read();
          // break when end of the line
          if (c == '\n') {
            break;
          }
          builder.append(c);
        }

        if (builder.length() > 0) {
          break;
        }

        if (pointer < 0) {
          return "";
        }
      }

      // Since line is read from the last, so it
      // is in reverse so use reverse method to make it right
      builder.reverse();

      return builder.toString();
    }
  }

  /**
   * Copied from the apache commons io project.
   *
   * <p>Deletes a directory recursively.
   *
   * @param directory - directory to delete
   * @throws IOException in case deletion is unsuccessful
   * @throws IllegalArgumentException
   *         if {@code directory} does not exist or is not a directory
   */
  public static void deleteDirectory(File directory) throws IOException {
    if (!directory.exists()) {
      return;
    }

    if (!isSymlink(directory)) {
      cleanDirectory(directory);
    }

    if (!directory.delete()) {
      throw new IOException("Unable to delete directory " + directory + ".");
    }
  }

  /**
   * Copied from the apache commons io project
   *
   * <p>Determines whether the specified file is a Symbolic Link rather than an
   * actual file.
   *
   * <p>Will not return true if there is a Symbolic Link anywhere in the path,
   * only if the specific file is.
   *
   * <p>For code that runs on Java 1.7 or later, use the following method
   * instead:
   * <br>
   * {@code boolean java.nio.file.Files.isSymbolicLink(Path path)}
   * @param file - the file to check
   * @return true if the file is a Symbolic Link
   * @throws IOException if an IO error occurs while checking the file
   */
  private static boolean isSymlink(File file) throws IOException {
    Args.notNull(file, "file");

    if (System.getProperty("os.name").toLowerCase().startsWith("windows")) {
      return false;
    }

    File fileInCanonicalDir = (file.getParent() == null) ? file
        : new File(file.getParentFile().getCanonicalFile(), file.getName());

    return !fileInCanonicalDir.getCanonicalFile().equals(fileInCanonicalDir.getAbsoluteFile());
  }

  /**
   * Copied from the apache commons io project
   *
   * <p>Cleans a directory without deleting it.
   *
   * @param directory - directory to clean
   * @throws IOException in case cleaning is unsuccessful
   * @throws IllegalArgumentException
   *         if {@code directory} does not exist or is not a directory
   */
  private static void cleanDirectory(File directory) throws IOException {
    if (!directory.exists()) {
      throw new IllegalArgumentException(directory + " does not exist");
    }

    if (!directory.isDirectory()) {
      throw new IllegalArgumentException(directory + " is not a directory");
    }

    final File[] files = directory.listFiles();
    // null if security restricted
    if (files == null) {
      throw new IOException("Failed to list contents of " + directory);
    }

    IOException exception = null;
    for (final File file : files) {
      try {
        forceDelete(file);
      } catch (final IOException ioe) {
        exception = ioe;
      }
    }

    if (null != exception) {
      throw exception;
    }
  }

  /**
   * Copied from the apache commons io project
   *
   * <p>Deletes a file. If file is a directory, delete it and all
   * subdirectories.
   *
   * <p>The difference between File.delete() and this method are:
   * <ul>
   * <li>A directory to be deleted does not have to be empty.</li>
   * <li>You get exceptions when a file or directory may not be deleted.
   *        (java.io.File methods returns a boolean)</li>
   * </ul>
   *
   * @param file - file or directory to delete, may not be {@code null}
   * @throws NullPointerException if the directory is {@code null}
   * @throws FileNotFoundException if the file was not found
   * @throws IOException in case deletion is unsuccessful
   */
  private static void forceDelete(File file) throws IOException {
    if (file.isDirectory()) {
      deleteDirectory(file);
      return;
    }

    final boolean filePresent = file.exists();
    if (!file.delete()) {
      if (!filePresent) {
        throw new FileNotFoundException("File does not exist: " + file);
      }
      throw new IOException("Unable to delete file: " + file);
    }
  }

  /**
   * Copied from the apache commons io project
   *
   * <p>Internal copy file method.
   * This caches the original file length, and an IOException will be thrown
   * if the output file length is different from the current input file length.
   * So it may fail if the file changes size.
   * It may also fail with "IllegalArgumentException: Negative size" if the
   * input file is truncated part way through copying the data and the new file
   * size is less than the current position.
   *
   * @param srcFile - the validated source file, may not be {@code null}
   * @param destFile - the validated destination file, may not be {@code null}
   * @param preserveFileDate whether to preserve the file date
   * @throws IOException
   *         if the output file length is not the same as the input file length
   *         after the copy completes
   * @throws IllegalArgumentException
   *         "Negative size" if the file is truncated so that the size is less
   *         than the position
   */
  public static void copyFile(File srcFile, File destFile, boolean preserveFileDate)
      throws IOException {
    if (destFile.exists() && destFile.isDirectory()) {
      throw new IOException("Destination '" + destFile + "' exists but is a directory");
    }

    Files.copy(srcFile.toPath(), destFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
    if (preserveFileDate) {
      destFile.setLastModified(srcFile.lastModified());
    }
  }

  public static void copyDirectory(File srcDir, File destDir) throws IOException {
    copyDirectory(srcDir, destDir, null, true, null);
  }

  /**
   * Copied from the apache commons io project
   *
   * <p>Internal copy directory method.
   *
   * @param srcDir the validated source directory, may not be {@code null}
   * @param destDir the validated destination directory, may not be
   *                {@code null}
   * @param filter the filter to apply, null means copy all directories and
   *               files
   * @param preserveFileDate whether to preserve the file date
   * @param exclusionList List of files and directories to exclude from the
   *                      copy, may be null.
   * @throws IOException if an error occurs
   */
  private static void copyDirectory(
      File srcDir, File destDir, FileFilter filter, boolean preserveFileDate,
      List<String> exclusionList) throws IOException {
    // recurse
    final File[] srcFiles = (filter == null)
        ? srcDir.listFiles() : srcDir.listFiles(filter);
    if (srcFiles == null) {
      // null if abstract pathname does not denote a directory, or if an I/O
      // error occurs
      throw new IOException("Failed to list contents of " + srcDir);
    }

    if (destDir.exists()) {
      if (!destDir.isDirectory()) {
        throw new IOException("Destination '" + destDir + "' exists but is not a directory");
      }
    } else {
      if (!destDir.mkdirs() && !destDir.isDirectory()) {
        throw new IOException("Destination '" + destDir + "' directory cannot be created");
      }
    }

    if (!destDir.canWrite()) {
      throw new IOException("Destination '" + destDir + "' cannot be written to");
    }

    for (final File srcFile : srcFiles) {
      final File dstFile = new File(destDir, srcFile.getName());
      if (exclusionList == null || !exclusionList.contains(srcFile.getCanonicalPath())) {
        if (srcFile.isDirectory()) {
          copyDirectory(srcFile, dstFile, filter, preserveFileDate, exclusionList);
        } else {
          copyFile(srcFile, dstFile, preserveFileDate);
        }
      }
    }

    // Do this last, as the above has probably affected directory metadata
    if (preserveFileDate) {
      destDir.setLastModified(srcDir.lastModified());
    }
  }

  /**
   * Read exactly number of bytes from the input stream.
   * The specified stream remains open after this method returns.
   * @param in the input stream.
   * @param len length of bytes to read from the input stream in.
   * @return the bytes read from in.
   * @throws IOException if error occurs while reading the bytes or
   *         not enough bytes are available.
   */
  public static byte[] readExactBytes(InputStream in, int len) throws IOException {
    byte[] ret = new byte[len];
    readExactBytes(in, ret, 0, len);
    return ret;
  }

  /**
   * Read exactly number of bytes from the input stream.
   * The specified stream remains open after this method returns.
   * @param in the input stream.
   * @param out to which the bytes is written.
   * @param off off set out to which the byts is written to.
   * @param len length of bytes to read from the input stream in.
   * @throws IOException if error occurs while reading the bytes or
   *         not enough bytes are available..
   */
  public static void readExactBytes(InputStream in, byte[] out, int off, int len)
      throws IOException {
    int read = in.readNBytes(out, off, len);
    if (read < len) {
      throw new IOException("in reaches end, but still expected " + (len - read) + " bytes");
    }
  }

  /**
   * Read all bytes from the input stream.
   * The specified stream remains open after this method returns.
   * @param in the input stream.
   * @return the byte array contained in the input stream.
   * @throws IOException if error occurs while reading the bytes.
   */
  public static byte[] readAllBytes(InputStream in) throws IOException {
    return in.readAllBytes();
  }

  public static String getHostAddress() throws SocketException {
    List<String> addresses = new LinkedList<>();

    Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();

    while (interfaces.hasMoreElements()) {
      NetworkInterface ni = interfaces.nextElement();
      Enumeration<InetAddress> ee = ni.getInetAddresses();
      while (ee.hasMoreElements()) {
        InetAddress ia = ee.nextElement();
        if (ia instanceof Inet4Address) {
          addresses.add(ia.getHostAddress());
        }
      }
    }

    for (String addr : addresses) {
      if (!addr.startsWith("192.") && !addr.startsWith("127.")) {
        return addr;
      }
    }

    for (String addr : addresses) {
      if (!addr.startsWith("127.")) {
        return addr;
      }
    }

    if (!addresses.isEmpty()) {
      return addresses.get(0);
    } else {
      try {
        return InetAddress.getLocalHost().getHostAddress();
      } catch (UnknownHostException ex) {
        return "UNKNOWN";
      }
    }
  }

  public static HttpURLConnection openHttpConn(URL url) throws IOException {
    URLConnection conn = Args.notNull(url, "url").openConnection();
    if (conn instanceof HttpURLConnection) {
      return (HttpURLConnection) conn;
    }
    throw new IOException(url + " is not of protocol HTTP: " + url.getProtocol());
  }
}
