package org.vaultkern.android.storage;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import java.io.File;
import java.io.FileNotFoundException;

public final class TestLocalDocumentProvider extends ContentProvider {
    private File root() {
        return new File(getContext().getNoBackupFilesDir(), "test-local-document-provider");
    }

    @Override
    public boolean onCreate() {
        File root = root();
        return root.mkdirs() || root.isDirectory();
    }

    @Override
    public String getType(Uri uri) {
        return "application/x-keepass2";
    }

    @Override
    public Cursor query(
            Uri uri,
            String[] projection,
            String selection,
            String[] selectionArgs,
            String sortOrder) {
        String[] columns = projection != null
                ? projection
                : new String[] {
                    OpenableColumns.DISPLAY_NAME,
                    OpenableColumns.SIZE,
                    DocumentsContract.Document.COLUMN_LAST_MODIFIED
                };
        File file = file(uri);
        Object[] row = new Object[columns.length];
        for (int index = 0; index < columns.length; index++) {
            String column = columns[index];
            if (OpenableColumns.DISPLAY_NAME.equals(column)) {
                row[index] = file.getName();
            } else if (OpenableColumns.SIZE.equals(column)) {
                row[index] = file.length();
            } else if (DocumentsContract.Document.COLUMN_LAST_MODIFIED.equals(column)) {
                row[index] = file.lastModified();
            }
        }
        MatrixCursor cursor = new MatrixCursor(columns);
        cursor.addRow(row);
        return cursor;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        File root = root();
        if (!root.mkdirs() && !root.isDirectory()) {
            throw new FileNotFoundException("test provider root is unavailable");
        }
        return ParcelFileDescriptor.open(file(uri), ParcelFileDescriptor.parseMode(mode));
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return file(uri).delete() ? 1 : 0;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int update(
            Uri uri,
            ContentValues values,
            String selection,
            String[] selectionArgs) {
        return 0;
    }

    private File file(Uri uri) {
        String name = uri.getLastPathSegment();
        if (name == null || !name.equals(new File(name).getName())) {
            throw new IllegalArgumentException("invalid test document name");
        }
        return new File(root(), name);
    }
}
