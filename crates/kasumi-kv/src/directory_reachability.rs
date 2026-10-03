//! Exact page membership through one bounded directory path.

use super::*;

impl DirectoryReader<'_> {
    /// Check whether an exact cached page is reachable from one immutable root.
    /// The candidate's minimum key and level borrow its already-owned bytes;
    /// only one admitted page buffer and fixed bounds are needed for descent.
    /// A reachable page must occupy that minimum key's unique path at its level.
    /// Every visited ancestor and the final page are checked against their
    /// parent bounds. The complete arena/index/digest identity must match.
    ///
    /// Candidate validation is independent of this root's generation, so a
    /// newer canonical candidate is simply absent from a historical root.
    /// Malformed candidates are errors even for an empty or older root. On an
    /// exact reference match, the validated candidate supplies the page bytes
    /// without another backend read. Otherwise at most `root.height` pages are
    /// read; no sibling subtrees or persistent root/page lists are collected.
    ///
    /// This is only one-root membership, not reclamation authority. A cache
    /// owner must cover its selected root and every relevant pin under its
    /// publication lock before removing an identity. Output guards retain
    /// their original allocation. Use a policy-neutral backend for maintenance
    /// so proof reads neither fill the cache nor train demand policy.
    pub(crate) fn contains_page(
        &self,
        root: DirectoryRoot,
        candidate: DirectoryPageRef,
        bytes: &[u8],
    ) -> Result<bool, CoreError> {
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        let result = (|| {
            root.validate()?;
            // validate_page uses the root's group and generation ceiling. A
            // maximum ceiling validates the candidate itself before applying
            // the historical root's independent eligibility constraints.
            let info = validate_page(
                bytes,
                DirectoryRoot {
                    generation: u64::MAX,
                    ..root
                },
                candidate,
            )?;
            let Some(reference) = root.page else {
                return Ok(false);
            };
            let _workspace = reserve(
                &self.admission,
                std::mem::size_of::<Bounds>()
                    + 2 * std::mem::size_of::<PageInfo>()
                    + 2 * std::mem::size_of::<Entry<'_>>(),
            )?;
            if reference == candidate {
                Bounds::root(root).check(bytes, info)?;
                return Ok(true);
            }
            let mut input = PageBuffer::new(&self.admission)?;
            self.contains_page_in(root, candidate, bytes, info, &mut input)
        })();
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        result
    }

    /// The same exact membership proof with no new reservation or buffer
    /// allocation. Workspace ownership and all candidate/path checks still
    /// apply, including for empty roots and direct root-reference hits.
    pub(crate) fn contains_page_with_workspace(
        &self,
        root: DirectoryRoot,
        candidate: DirectoryPageRef,
        bytes: &[u8],
        workspace: &mut DirectoryReadWorkspace,
    ) -> Result<bool, CoreError> {
        workspace.check(&self.admission)?;
        let result = (|| {
            root.validate()?;
            let info = validate_page(
                bytes,
                DirectoryRoot {
                    generation: u64::MAX,
                    ..root
                },
                candidate,
            )?;
            self.contains_page_in(root, candidate, bytes, info, &mut workspace.buffer)
        })();
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        result
    }

    fn contains_page_in(
        &self,
        root: DirectoryRoot,
        candidate: DirectoryPageRef,
        bytes: &[u8],
        info: PageInfo,
        input: &mut [u8],
    ) -> Result<bool, CoreError> {
        let Some(mut reference) = root.page else {
            return Ok(false);
        };
        let minimum = nth_entry(bytes, info, 0)?.key;
        let mut bounds = Bounds::root(root);
        if reference == candidate {
            bounds.check(bytes, info)?;
            return Ok(true);
        }
        loop {
            let parent = self.load(input, root, reference, &bounds)?;
            if parent.level <= info.level {
                return Ok(false);
            }
            let mut child = 0;
            let mut at = HEADER_BYTES;
            for index in 0..parent.count {
                let (entry, end) = page_entry(input, at, parent.used)?;
                if entry.key > minimum {
                    break;
                }
                child = index;
                at = end;
            }
            // Even a key below the first separator follows the first
            // child. Its bounds must be checked before proving absence.
            reference = bounds.child(input, parent, child)?;
            if reference == candidate {
                bounds.check(bytes, info)?;
                return Ok(true);
            }
        }
    }
}
