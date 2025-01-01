import cloudinary.uploader



def upload_to_cloudinary(file, folder="project_folder", tags=None, transformation=None):
    tags = tags or ['certificate_upload']
    transformation = transformation or {"width": 300, "height": 300, "crop": "fill"}
    
    # Validation checks
    if not hasattr(file, 'read'):
        raise ValueError("Invalid file object. The file must be a file-like object.")
    if not isinstance(folder, str) or not all(c.isalnum() or c in ['-', '_'] for c in folder):
        raise ValueError("Folder name must be alphanumeric, dashes, or underscores.")
    if not all(isinstance(tag, str) for tag in tags):
        raise ValueError("All tags must be strings.")

    try:
        upload_result = cloudinary.uploader.upload(
            file,
            folder=folder,
            tags=tags,
            transformation=transformation
        )
        print(f"Upload successful: {upload_result['secure_url']}")
        return upload_result
    except cloudinary.exceptions.Error as e:
        raise Exception(f"Cloudinary upload failed: {str(e)}")
    except Exception as e:
        raise Exception(f"An unexpected error occurred during Cloudinary upload: {str(e)}")
