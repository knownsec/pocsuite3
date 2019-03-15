import zipfile


class Zip:
    def __init__(self, filename=''):
        self.name = filename
        self.files = set()
        if filename:
            self.create_archieve(filename)

    def create_archieve(self, filename):
        if not self.name:
            self.name = filename
        zf = zipfile.ZipFile(filename, 'w')
        zf.close()

    def add_file(self, name, content=''):
        if not self.is_valid(name):
            return
        zf = zipfile.ZipFile(self.name, 'a')
        if content:
            zf.writestr(name, content)
        else:
            zf.write(name)
        zf.close()
        self.files.add(name)

    def is_valid(self, filename=''):
        if not self.name:
            raise Exception("Error. Zip archieve is not created.")
            return False
        if not zipfile.is_zipfile(self.name):
            raise Exception("Error. File {name} is not zip archieve.".format(name=self.name))
            return False
        if filename and filename in self.files:
            raise Exception("Error. There is file with the same name.")
            return False
        return True
